<#
.SYNOPSIS
    Create a bulk of Active Directory user accounts from a CSV file.

.DESCRIPTION
    Reads a CSV file where each row represents a new user, then creates each
    account using the same username, display name, and password logic as
    New-ADUser.ps1.

    The CSV must have the following columns:
        FirstName   - Required
        LastName    - Required
        Department  - Required
        Title       - Required
        OU          - Required. Distinguished Name, e.g. OU=IT,DC=mdc,DC=lab
        MiddleName  - Optional. Leave blank to skip
        Groups      - Optional. Specify one or more group names separated by a semicolon (e.g. "HR-Users;Shared-Drive-HR")

    Password options (choose one via parameters):
        -SharedPassword : One SecureString used for every account (for onboarding, all users must reset on first login)
        -PromptPerUser  : Prompts for a password individually for each row

.PARAMETER CsvPath
    Path to the CSV file to import.

.PARAMETER Domain
    The domain suffix used for UPNs and email addresses.

.PARAMETER SharedPassword
    A single SecureString password applied to all created accounts:
    -SharedPassword (Read-Host "Password" -AsSecureString)

.PARAMETER PromptPerUser
    If specified, prompts for a unique password for each user row instead of
    using a shared password.

.PARAMETER ReportPath
    Optional path to export a CSV summary report of results.
    By default, CSV is exported to the Reports folder relative to this script.

.EXAMPLE
    # Use a shared password for all users
    .\New-ADUsersFromCSV.ps1 -CsvPath .\new-hires.csv -Domain "mdc.lab" -SharedPassword (Read-Host "Shared Password" -AsSecureString)

.EXAMPLE
    # Prompt for each user's password individually
    .\New-ADUsersFromCSV.ps1 -CsvPath .\new-hires.csv -Domain "mdc.lab" -PromptPerUser

.EXAMPLE
    # Use a shared password and export a report
    .\New-ADUsersFromCSV.ps1 -CsvPath .\new-hires.csv -Domain "mdc.lab" -SharedPassword (Read-Host "Shared Password" -AsSecureString) -ReportPath "C:\Reports\bulk-import.csv"
#>

#Requires -Modules ActiveDirectory

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Shared')]
param (
    [Parameter(Mandatory)]
    [string]$CsvPath,

    [Parameter(Mandatory)]
    [string]$Domain,

    [Parameter(Mandatory, ParameterSetName = 'Shared')]
    [SecureString]$SharedPassword,

    [Parameter(Mandatory, ParameterSetName = 'PerUser')]
    [switch]$PromptPerUser,

    [Parameter()]
    [string]$ReportPath
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

    $firstInitial   = $FirstName.Substring(0, 1).ToLower()
    $middleInitial  = if ($MiddleName) { $MiddleName.Substring(0, 1).ToLower() } else { '' }
    $lastClean      = $LastName.ToLower() -replace '[^a-z0-9]', ''

    $baseUsername   = ($firstInitial + $lastClean) -replace '[^a-z0-9]', ''
    $baseWithMiddle = ($firstInitial + $middleInitial + $lastClean) -replace '[^a-z0-9]', ''

    $currentUsername = $baseUsername
    $suffixNumber    = 2

    while (Get-ADUser -Filter "SamAccountName -eq '$currentUsername'" -ErrorAction SilentlyContinue) {
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

    $middleInitial  = if ($MiddleName) { $MiddleName.Substring(0, 1).ToUpper() } else { '' }
    $baseName       = "$FirstName $LastName"
    $nameWithMiddle = if ($middleInitial) { "$FirstName $middleInitial. $LastName" } else { $null }

    $baseUsernames = @(
        $baseName
        if ($nameWithMiddle -and $nameWithMiddle -ne $baseName) { $nameWithMiddle }
    )

    foreach ($baseUsername in $baseUsernames) {
        if (-not (Get-ADObject -Filter "Name -eq '$baseUsername'" -SearchBase $OU -ErrorAction SilentlyContinue)) {
            return $baseUsername
        }
    }

    $suffixNumber = 2
    while ($true) {
        $baseUsername = "$baseName ($suffixNumber)"
        if (-not (Get-ADObject -Filter "Name -eq '$baseUsername'" -SearchBase $OU -ErrorAction SilentlyContinue)) {
            return $baseUsername
        }
        $suffixNumber++
    }
}

# -----------------------------------------------------------------------
# Password
# -----------------------------------------------------------------------
function Test-PasswordPolicy {
    param (
        [string]$PlainText,
        [Microsoft.ActiveDirectory.Management.ADDefaultDomainPasswordPolicy]$Policy
    )

    $failures = @()

    if ($PlainText.Length -lt $Policy.MinPasswordLength) {
        $failures += "At least $($Policy.MinPasswordLength) characters (currently $($PlainText.Length))"
    }

    if ($Policy.ComplexityEnabled) {
        $hasUpper  = $PlainText -cmatch '[A-Z]'
        $hasLower  = $PlainText -cmatch '[a-z]'
        $hasDigit  = $PlainText -match  '[0-9]'
        $hasSymbol = $PlainText -match  '[^a-zA-Z0-9]'
        $metCount  = @($hasUpper, $hasLower, $hasDigit, $hasSymbol) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count

        if ($metCount -lt 3) {
            $failures += "Complexity: must meet 3 of 4 categories (uppercase, lowercase, numbers, symbols)"
        }
    }

    return $failures
}

function Read-ValidPassword {
    param (
        [string]$Prompt,
        [Microsoft.ActiveDirectory.Management.ADDefaultDomainPasswordPolicy]$Policy
    )

    do {
        $securePassword = Read-Host $Prompt -AsSecureString
        $bstr           = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
        $plainText      = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) # Clear the plain text from memory as soon as we're done with it
        $failures       = Test-PasswordPolicy -PlainText $plainText -Policy $Policy

        if ($failures.Count -gt 0) {
            Write-Warning "Password does not meet domain requirements:"
            $failures | ForEach-Object { Write-Warning "  - $_" }
            $securePassword = $null
        }
    } while (-not $securePassword)

    return $securePassword
}

# -----------------------------------------------------------------------
# Validate the CSV path
# -----------------------------------------------------------------------
if (-not (Test-Path $CsvPath)) {
    Write-Error "CSV file not found: '$CsvPath'"
    exit 1
}

$users = Import-Csv -Path $CsvPath

if ($users.Count -eq 0) {
    Write-Error "The CSV file is empty."
    exit 1
}

# Validate required columns exist
$requiredColumns = @('FirstName', 'LastName', 'Department', 'Title', 'OU')
$csvColumns      = $users[0].PSObject.Properties.Name
$missingColumns  = $requiredColumns | Where-Object { $_ -notin $csvColumns }

if ($missingColumns.Count -gt 0) {
    Write-Error "CSV is missing required column(s): $($missingColumns -join ', ')"
    exit 1
}

# -----------------------------------------------------------------------
# Retrieve and display password policy once for the whole run
# -----------------------------------------------------------------------
Write-Host "`nRetrieving domain password policy..." -ForegroundColor Cyan
$policy = Get-ADDefaultDomainPasswordPolicy
Write-Host "  Minimum Length      : $($policy.MinPasswordLength) characters"
Write-Host "  Complexity Required : $($policy.ComplexityEnabled)"
Write-Host "  Password History    : Last $($policy.PasswordHistoryCount) passwords cannot be reused"

# Validate shared password upfront before processing any rows
if ($PSCmdlet.ParameterSetName -eq 'Shared') {
    $bstr      = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SharedPassword)
    $plainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) # Clear the plain text from memory as soon as we're done with it
    $failures  = Test-PasswordPolicy -PlainText $plainText -Policy $policy

    if ($failures.Count -gt 0) {
        Write-Warning "The shared password does not meet domain requirements:"
        $failures | ForEach-Object { Write-Warning "  - $_" }
        $SharedPassword = Read-ValidPassword -Prompt "Enter a valid shared password" -Policy $policy
    }
    else {
        Write-Host "  Shared password     : Validated OK" -ForegroundColor Green
    }
}

# -----------------------------------------------------------------------
# Process each row
# -----------------------------------------------------------------------
Write-Host "`nImporting $($users.Count) user(s) from '$CsvPath'..." -ForegroundColor Cyan

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$rowNumber = 0

foreach ($row in $users) {
    $rowNumber++
    $firstName  = $row.FirstName.Trim()
    $lastName   = $row.LastName.Trim()
    $middleName = if ($row.PSObject.Properties['MiddleName']) { $row.MiddleName.Trim() } else { '' }
    $department = $row.Department.Trim()
    $title      = $row.Title.Trim()
    $ou         = $row.OU.Trim()
    $groups     = if ($row.PSObject.Properties['Groups'] -and $row.Groups) {
                      $row.Groups -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                  } else { @() }

    Write-Host "`n[$rowNumber/$($users.Count)] Processing: $firstName $lastName" -ForegroundColor Cyan

    # Validate Organizational Unit format
    if ($ou -notmatch '^(OU|CN)=[^,]+(,(OU|CN)=[^,]+)*,DC=[^,]+(,DC=[^,]+)+$') {
        Write-Host "  [Failed] Invalid OU format '$ou'. Must be a Distinguished Name e.g. 'OU=IT,DC=mdc,DC=lab'." -ForegroundColor Red
        $results.Add([PSCustomObject]@{
            Row         = $rowNumber
            DisplayName = "$firstName $lastName"
            Username    = 'N/A'
            Email       = 'N/A'
            OU          = $ou
            Status      = 'Failed'
            Reason      = "Invalid OU format"
        })
        continue
    }

    # Validate Organizational Unit exists
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ou'" -ErrorAction SilentlyContinue)) {
        Write-Host "  [Failed] OU '$ou' does not exist in AD." -ForegroundColor Red
        $results.Add([PSCustomObject]@{
            Row         = $rowNumber
            DisplayName = "$firstName $lastName"
            Username    = 'N/A'
            Email       = 'N/A'
            OU          = $ou
            Status      = 'Failed'
            Reason      = "OU not found in AD"
        })
        continue
    }

    # Resolve unique username and display name
    $username    = Get-UniqueUsername -FirstName $firstName -MiddleName $middleName -LastName $lastName
    $displayName = Get-UniqueDisplayName -FirstName $firstName -MiddleName $middleName -LastName $lastName -OU $ou
    $upn         = "$username@$Domain"

    # Email
    $middleInitial = if ($middleName) { $middleName.Substring(0, 1).ToLower() } else { '' }
    $emailBase = if ($middleInitial -and $username -match "^$($firstName.Substring(0,1).ToLower())$middleInitial") {
        "$($firstName.ToLower()).$middleInitial.$($lastName.ToLower())"
    } else {
        "$($firstName.ToLower()).$($lastName.ToLower())"
    }
    $emailBase = $emailBase -replace '[^a-z0-9.]', ''
    $email     = "$emailBase@$Domain"

    Write-Host "  Display Name : $displayName"
    Write-Host "  Username     : $username"
    Write-Host "  UPN          : $upn"
    Write-Host "  Email        : $email"

    # Password
    $password = if ($PSCmdlet.ParameterSetName -eq 'PerUser') {
        Read-ValidPassword -Prompt "  Password for $username" -Policy $policy
    } else {
        $SharedPassword
    }

    # Create user
    try {
        New-ADUser `
            -Name                  $displayName `
            -DisplayName           $displayName `
            -GivenName             $firstName `
            -Surname               $lastName `
            -SamAccountName        $username `
            -UserPrincipalName     $upn `
            -EmailAddress          $email `
            -Department            $department `
            -Title                 $title `
            -Path                  $ou `
            -AccountPassword       $password `
            -Enabled               $true `
            -ChangePasswordAtLogon $true

        Write-Host "  [Success] Created successfully." -ForegroundColor Green

        # Add to groups if specified
        foreach ($group in $groups) {
            try {
                Add-ADGroupMember -Identity $group -Members $username
                Write-Host "    [Success] Added to group '$group'" -ForegroundColor Green
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                Write-Warning "    Group '$group' not found in AD, skipped."
            }
            catch {
                Write-Warning "    Could not add to group '$group': $_"
            }
        }

        $results.Add([PSCustomObject]@{
            Row         = $rowNumber
            DisplayName = $displayName
            Username    = $username
            Email       = $email
            OU          = $ou
            Status      = 'Success'
            Reason      = ''
        })
    }
    catch {
        Write-Host "  [Failed] $_" -ForegroundColor Red
        $results.Add([PSCustomObject]@{
            Row         = $rowNumber
            DisplayName = $displayName
            Username    = $username
            Email       = $email
            OU          = $ou
            Status      = 'Failed'
            Reason      = $_.Exception.Message
        })
    }
}

# -----------------------------------------------------------------------
# Summary table
# -----------------------------------------------------------------------
$successCount = ($results | Where-Object { $_.Status -eq 'Success' }).Count
$failCount    = ($results | Where-Object { $_.Status -eq 'Failed'  }).Count

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Bulk Import Complete" -ForegroundColor Cyan
Write-Host "  Total : $($users.Count)  |  " -ForegroundColor Cyan -NoNewline
Write-Host "Created : $successCount" -ForegroundColor Green -NoNewline
Write-Host "  |  " -ForegroundColor Cyan -NoNewline
if ($failCount -gt 0) {
    Write-Host "Failed : $failCount" -ForegroundColor Red
} else {
    Write-Host "Failed : $failCount" -ForegroundColor Cyan
}
Write-Host "========================================" -ForegroundColor Cyan

# Print each result
foreach ($result in $results) {
    $color = if ($result.Status -eq 'Success') { 'Green' } else { 'Red' }
    $line  = "  [{0}] Row {1} - {2} ({3})" -f $result.Status, $result.Row, $result.DisplayName, $result.Username
    if ($result.Reason) { $line += " - $($result.Reason)" }
    Write-Host $line -ForegroundColor $color
}
Write-Host ""

$results | Format-Table -AutoSize -Property Row, DisplayName, Username, Email, Status, Reason

# -----------------------------------------------------------------------
# Export report CSV
# -----------------------------------------------------------------------
if (-not $ReportPath) {
    $reportDir  = Join-Path (Split-Path $PSScriptRoot -Parent) 'Reports'
    $timestamp  = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $ReportPath = Join-Path $reportDir "BulkImport_$timestamp.csv"
}

$reportDir = Split-Path $ReportPath -Parent
if (-not (Test-Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir | Out-Null
}

$results | Export-Csv -Path $ReportPath -NoTypeInformation
Write-Host "`nReport saved to: $ReportPath" -ForegroundColor Green
