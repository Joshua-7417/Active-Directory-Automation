<#
.SYNOPSIS
    Automates the creation of a new Active Directory user account.

.DESCRIPTION
    This script creates a new AD user with a standardized username format,
    assigns them to a specified Organizational Unit (OU), sets an initial
    password, and optionally adds them to one or more security groups.

.PARAMETER FirstName
    The user's first name.

.PARAMETER LastName
    The user's last name.

.PARAMETER Department
    The user's department (e.g. "IT", "HR", "Finance").

.PARAMETER Title
    The user's job title (e.g. "Systems Administrator").

.PARAMETER OU
    The Distinguished Name of the OU to place the user in (e.g. "OU=Users,OU=IT,DC=mdc,DC=lab").

.PARAMETER Domain
    The domain suffix used for the UPN and email address (e.g. "mcd.lab").

.PARAMETER InitialPassword
    The temporary password assigned to the account as a SecureString. The user will be
    forced to change it on first login. Pass it using:
    -InitialPassword (Read-Host "Password" -AsSecureString)

.PARAMETER Groups
    An optional array of AD group names to add the user to after creation.

.EXAMPLE
    .\New-ADUser.ps1 `
        -FirstName "John" `
        -MiddleName "James" `
        -LastName "Smith" `
        -Department "Finance" `
        -Title "Accountant" `
        -OU "OU=Users,OU=Finance,DC=mdc,DC=lab" `
        -Domain "mdc.lab" `
        -Groups "Finance-Users", "VPN-Access" `
        -InitialPassword (Read-Host "Password" -AsSecureString)
#>

#Requires -Modules ActiveDirectory

# SupportsShouldProcess enables the -WhatIf and -Confirm parameters
# Allows user to simulate or confirm potentially destructive actions
[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)]
    [string]$FirstName,

    [Parameter()]
    [string]$MiddleName = '',

    [Parameter(Mandatory)]
    [string]$LastName,

    [Parameter(Mandatory)]
    [string]$Department,

    [Parameter(Mandatory)]
    [string]$Title,

    [Parameter()]
    [string]$OU,

    [Parameter(Mandatory)]
    [string]$Domain,

    [Parameter()]
    [SecureString]$InitialPassword,

    [Parameter()]
    [string[]]$Groups = @()
)

# -----------------------------------------------------------------------
# Username (SamAccountName)
# -----------------------------------------------------------------------
function Get-UniqueUsername {
    param (
        [string]$FirstName,
        [string]$MiddleName,
        [string]$LastName
    )

    $firstInitial  = $FirstName.Substring(0, 1).ToLower()
    $middleInitial = if ($MiddleName) { $MiddleName.Substring(0, 1).ToLower() } else { '' }
    $lastClean     = $LastName.ToLower() -replace '[^a-z0-9]', ''

    # Try first initial + last  (e.g. jsmith)
    $baseUsername = ($firstInitial + $lastClean) -replace '[^a-z0-9]', ''

    # Try first initial + middle initial + last  (e.g. jjsmith)
    $baseWithMiddle = ($firstInitial + $middleInitial + $lastClean) -replace '[^a-z0-9]', ''

    $currentUsername = $baseUsername
    $suffixNumber    = 2

    while (Get-ADUser -Filter "SamAccountName -eq '$currentUsername'" -ErrorAction SilentlyContinue) {
        Write-Verbose "Username '$currentUsername' already exists, trying next..."

        # Step up to the middle initial variant before resorting to numbers
        if ($currentUsername -eq $baseUsername -and $middleInitial -and $baseWithMiddle -ne $baseUsername) {
            $currentUsername = $baseWithMiddle
        }
        else {
            $currentUsername = "$baseUsername$suffixNumber"
            $suffixNumber++
        }
    }

    return $currentUsername
}

# -----------------------------------------------------------------------
# Display Name (CN)
# -----------------------------------------------------------------------
function Get-UniqueDisplayName {
    param (
        [string]$FirstName,
        [string]$MiddleName,
        [string]$LastName,
        [string]$OU
    )

    $middleInitial = if ($MiddleName) { $MiddleName.Substring(0, 1).ToUpper() } else { '' }
    $baseName      = "$FirstName $LastName"
    $nameWithMiddle = if ($middleInitial) { "$FirstName $middleInitial. $LastName" } else { $null }

    # Check if username is unique with or without middle initial
    $baseUsernames = @(
        $baseName
        if ($nameWithMiddle -and $nameWithMiddle -ne $baseName) { $nameWithMiddle }
    )

    foreach ($baseUsername in $baseUsernames) {
        if (-not (Get-ADObject -Filter "Name -eq '$baseUsername'" -SearchBase $OU -ErrorAction SilentlyContinue)) {
            return $baseUsername
        }
        Write-Verbose "Display name '$baseUsername' already exists in the target OU, trying next..."
    }

    # Fall through to numeric suffixes
    $suffixNumber = 2
    while ($true) {
        $baseUsername = "$baseName ($suffixNumber)"
        if (-not (Get-ADObject -Filter "Name -eq '$baseUsername'" -SearchBase $OU -ErrorAction SilentlyContinue)) {
            Write-Warning "Display name '$baseName' is already taken. Using '$baseUsername'."
            return $baseUsername
        }
        $suffixNumber++
    }
}

# -----------------------------------------------------------------------
# Assign user properties
# -----------------------------------------------------------------------
$FirstName  = $FirstName.Trim()
$LastName   = $LastName.Trim()

# Always prompt for middle name if not passed as a parameter
if (-not $MiddleName) {
    $MiddleName = (Read-Host "MiddleName (optional, press Enter to skip)").Trim()
} else {
    $MiddleName = $MiddleName.Trim()
}

# -----------------------------------------------------------------------
# Organizational Unit
# -----------------------------------------------------------------------
if (-not $OU) {
    Write-Host "`nRetrieving available Organizational Units..." -ForegroundColor Cyan
    $ouList = Get-ADOrganizationalUnit -Filter * |
              Select-Object -ExpandProperty DistinguishedName |
              Sort-Object

    for ($i = 0; $i -lt $ouList.Count; $i++) {
        Write-Host "  [$($i + 1)] $($ouList[$i])"
    }

    do {
        $ouChoice = Read-Host "`nEnter the number of the target Oranizational Unit"
        $ouIndex  = $ouChoice -as [int]
    } while (-not $ouIndex -or $ouIndex -lt 1 -or $ouIndex -gt $ouList.Count)

    $OU = $ouList[$ouIndex - 1]
    Write-Host "    Selected: $OU" -ForegroundColor Green
}

# -----------------------------------------------------------------------
# Password
# -----------------------------------------------------------------------
Write-Host "`nRetrieving domain password policy..." -ForegroundColor Cyan
$policy = Get-ADDefaultDomainPasswordPolicy
Write-Host "    Minimum Length      : $($policy.MinPasswordLength) characters"
Write-Host "    Complexity Required : $($policy.ComplexityEnabled)"
if ($policy.ComplexityEnabled) {
    Write-Host "    Complexity requirements: Must contain characters from 3 of the following 4 categories:" -ForegroundColor Yellow
    Write-Host "    Uppercase (A-Z)" -ForegroundColor Yellow
    Write-Host "    Lowercase (a-z)" -ForegroundColor Yellow
    Write-Host "    Numbers   (0-9)" -ForegroundColor Yellow
    Write-Host "    Symbols   (!@#`$%%^&* etc.)" -ForegroundColor Yellow
}
Write-Host "    Password History    : Last $($policy.PasswordHistoryCount) passwords cannot be reused"
Write-Host "    Max Password Age    : $($policy.MaxPasswordAge.Days) days"

# Prompt until the password meets all domain policy requirements
if (-not $InitialPassword) {
    do {
        $InitialPassword = Read-Host "`nInitialPassword" -AsSecureString
        $plainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($InitialPassword))

        $failures = @()

        # Check minimum length
        if ($plainText.Length -lt $policy.MinPasswordLength) {
            $failures += "At least $($policy.MinPasswordLength) characters (currently $($plainText.Length))"
        }

        # Check complexity if the policy requires it
        # AD complexity = must satisfy 3 of these 4 character categories
        if ($policy.ComplexityEnabled) {
            $hasUpper   = $plainText -cmatch '[A-Z]'
            $hasLower   = $plainText -cmatch '[a-z]'
            $hasDigit   = $plainText -match  '[0-9]'
            $hasSymbol  = $plainText -match  '[^a-zA-Z0-9]'
            $categories = @($hasUpper, $hasLower, $hasDigit, $hasSymbol) | Where-Object { $_ }

            if ($categories.Count -lt 3) {
                $failures += "Must contain at least 3 of the following 4 character categories:"
            }
        }

        if ($failures.Count -gt 0) {
            Write-Warning "Password does not meet the domain requirements:"
            $failures | ForEach-Object { Write-Warning "$_" }

            # If complexity Failed, show each category in green (met) or red (missing)
            if ($policy.ComplexityEnabled -and $categories.Count -lt 3) {
                Write-Host "  Complexity categories (need 3 of 4):" -ForegroundColor Yellow
                $categoryMap = @(
                    @{ Name = 'Uppercase letters (A-Z)';   Met = $hasUpper  }
                    @{ Name = 'Lowercase letters (a-z)';   Met = $hasLower  }
                    @{ Name = 'Numbers (0-9)';              Met = $hasDigit  }
                    @{ Name = 'Symbols (!@#$% etc.)';       Met = $hasSymbol }
                )
                foreach ($cat in $categoryMap) {
                    if ($cat.Met) {
                        Write-Host "    [+] $($cat.Name)" -ForegroundColor Green
                    } else {
                        Write-Host "    [-] $($cat.Name)" -ForegroundColor Red
                    }
                }
            }

            $InitialPassword = $null
        }
    } while (-not $InitialPassword)
}

$username    = Get-UniqueUsername -FirstName $FirstName -MiddleName $MiddleName -LastName $LastName
$upn         = "$username@$Domain"

# Display name
$displayName = Get-UniqueDisplayName -FirstName $FirstName -MiddleName $MiddleName -LastName $LastName -OU $OU
if (-not $displayName) {
    Write-Warning "All display name variants were taken. Using username '$username' as the display name."
    $displayName = $username
}

# Email
$middleInitial = if ($MiddleName) { $MiddleName.Substring(0, 1).ToLower() } else { '' }
$emailBase = if ($username -match "^$($FirstName.Substring(0,1).ToLower())$($middleInitial)") {
    # Username contains middle initial, reflect that in the email
    if ($middleInitial) { "$($FirstName.ToLower()).$middleInitial.$($LastName.ToLower())" }
    else                { "$($FirstName.ToLower()).$($LastName.ToLower())" }
} else {
    # Username had a numeric suffix, keep email as first.last to stay readable
    "$($FirstName.ToLower()).$($LastName.ToLower())"
}
$emailBase = $emailBase -replace '[^a-z0-9.]', ''
$email     = "$emailBase@$Domain"

# Convert the plain-text password into a SecureString, required by AD
$securePassword = $InitialPassword

Write-Host "Creating user account..." -ForegroundColor Cyan
Write-Host "    Display Name : $displayName"
Write-Host "    Username     : $username"
Write-Host "    UPN          : $upn"
Write-Host "    Email        : $email"
Write-Host "    Department   : $Department"
Write-Host "    Title        : $Title"
Write-Host "    Target OU    : $OU"

# -----------------------------------------------------------------------
# Create the AD user account
# -----------------------------------------------------------------------
try {
    New-ADUser `
        -Name              $displayName `
        -DisplayName       $displayName `
        -GivenName         $FirstName `
        -Surname           $LastName `
        -SamAccountName    $username `
        -UserPrincipalName $upn `
        -EmailAddress      $email `
        -Department        $Department `
        -Title             $Title `
        -Path              $OU `
        -AccountPassword   $securePassword `
        -Enabled           $true `
        -ChangePasswordAtLogon $true # Forces a password reset on first login

    Write-Host "`n[Success] User '$username' created successfully." -ForegroundColor Green
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
    # This handles the rare race condition where a duplicate username is created
    Write-Error "A user with the SamAccountName '$username' already exists in AD."
    exit 1
}
catch {
    Write-Error "Failed to create user '$username': $_"
    exit 1
}

# -----------------------------------------------------------------------
# Add the user to any specified groups
# -----------------------------------------------------------------------
if ($Groups.Count -gt 0) {
    Write-Host "`nAdding user to groups..." -ForegroundColor Cyan

    foreach ($group in $Groups) {
        try {
            Add-ADGroupMember -Identity $group -Members $username
            Write-Host "  [Success] Added to '$group'" -ForegroundColor Green
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Warning "  [Warning] Group '$group' was not found in AD."
        }
        catch {
            Write-Warning "  [Error] Could not add to '$group': $_"
        }
    }
}

# -----------------------------------------------------------------------
# Output a summary object, which may be used for logging or piping
# -----------------------------------------------------------------------
[PSCustomObject]@{
    DisplayName  = $displayName
    Username     = $username
    UPN          = $upn
    Email        = $email
    FirstName    = $FirstName
    MiddleName   = $MiddleName
    LastName     = $LastName
    Department   = $Department
    Title        = $Title
    OU           = $OU
    GroupsAdded  = $Groups
    CreatedOn    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}
