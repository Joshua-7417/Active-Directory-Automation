<#
.SYNOPSIS
    Resets the password for an existing Active Directory user account.

.DESCRIPTION
    This script resets the password for a specified AD user account, validates
    the new password against the domain password policy, and optionally forces
    the user to change their password on next login.

.PARAMETER Username
    The SamAccountName of the user whose password will be reset (e.g. "jsmith").

.PARAMETER Domain
    The domain to query the password policy from (e.g. "mdc.lab").

.PARAMETER NewPassword
    The new password as a SecureString. If not provided, the script will prompt
    for one and validate it against the domain password policy.

.PARAMETER ForceChangeAtLogon
    If specified, the user will be required to change their password on next login.
    Defaults to $true.

.EXAMPLE
    .\Set-ADUserPassword.ps1

.EXAMPLE
    .\Set-ADUserPassword.ps1 -Username "jsmith" -Domain "mdc.lab"

.EXAMPLE
    .\Set-ADUserPassword.ps1 -Username "jsmith" -Domain "mdc.lab" -ForceChangeAtLogon:$false
#>

#Requires -Modules ActiveDirectory

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory)][string]$Username,
    [Parameter(Mandatory)][string]$Domain,
    [SecureString]$NewPassword,
    [bool]$ForceChangeAtLogon = $true
)

# -----------------------------------------------------------------------
# Test password
# -----------------------------------------------------------------------
function Test-PasswordComplexity {
    param (
        [string]$PlainText,
        [Microsoft.ActiveDirectory.Management.ADDefaultDomainPasswordPolicy]$Policy
    )

    $failures = [System.Collections.Generic.List[string]]::new()

    if ($PlainText.Length -lt $Policy.MinPasswordLength) {
        $failures.Add("At least $($Policy.MinPasswordLength) characters (currently $($PlainText.Length))")
    }

    # Check complexity if the policy requires it
    # AD complexity = must satisfy 3 of these 4 character categories
    if ($Policy.ComplexityEnabled) {
        $hasUpper   = $PlainText -cmatch '[A-Z]'
        $hasLower   = $PlainText -cmatch '[a-z]'
        $hasDigit   = $PlainText -match  '[0-9]'
        $hasSymbol  = $PlainText -match  '[^a-zA-Z0-9]'
        $categories = @($hasUpper, $hasLower, $hasDigit, $hasSymbol) | Where-Object { $_ }

        if ($categories.Count -lt 3) {
            $failures.Add('Must contain at least 3 of the following 4 character categories:')
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

        $failures = @()

        # Check minimum length
        if ($plainText.Length -lt $Policy.MinPasswordLength) {
            $failures += "At least $($Policy.MinPasswordLength) characters (currently $($plainText.Length))"
        }

        # Check complexity if the policy requires it
        # AD complexity = must satisfy 3 of these 4 character categories
        if ($Policy.ComplexityEnabled) {
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
            if ($Policy.ComplexityEnabled -and $categories.Count -lt 3) {
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

            $securePassword = $null
        }
    } while (-not $securePassword)

    return $securePassword
}

# -----------------------------------------------------------------------
# Verify the user exists
# -----------------------------------------------------------------------
Write-Host ""

$adUser = $null

# If a username was passed as a parameter, try it first
if ($Username) {
    $adUser = Get-ADUser -Filter "SamAccountName -eq '$Username'" -Properties DisplayName -ErrorAction SilentlyContinue
    if (-not $adUser) {
        Write-Warning "User '$Username' was not found in Active Directory."
    }
}

# If still not resolved, show a numbered list of all users to pick from
if (-not $adUser) {
    Write-Host "`nRetrieving all AD users..." -ForegroundColor Cyan
    $allUsers = Get-ADUser -Filter * -Properties DisplayName |
                Sort-Object DisplayName

    for ($i = 0; $i -lt $allUsers.Count; $i++) {
        Write-Host "  [$($i + 1)] $($allUsers[$i].DisplayName) ($($allUsers[$i].SamAccountName))"
    }

    do {
        $userChoice = Read-Host "`nEnter the number of the user"
        $userIndex  = $userChoice -as [int]
    } while (-not $userIndex -or $userIndex -lt 1 -or $userIndex -gt $allUsers.Count)

    $adUser   = $allUsers[$userIndex - 1]
    $Username = $adUser.SamAccountName
    Write-Host "  Selected: $($adUser.DisplayName) ($Username)" -ForegroundColor Green
}

# -----------------------------------------------------------------------
# Password policy
# -----------------------------------------------------------------------
Write-Host "Retrieving domain password policy..." -ForegroundColor Cyan

try {
    $policy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
} catch {
    Write-Error "Failed to retrieve domain password policy: $_"
    exit 1
}

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
Write-Host ""

# -----------------------------------------------------------------------
# New password
# -----------------------------------------------------------------------
if (-not $NewPassword) {
    $NewPassword = Read-ValidPassword -Prompt "NewPassword (min $($policy.MinPasswordLength) chars)" -Policy $policy
} else {
    # Validate the provided password against policy before attempting the reset
    $bstr      = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword)
    $plainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)  # Clear the plain text from memory as soon as we're done with it
    $failures  = Test-PasswordComplexity -PlainText $plainText -Policy $policy

    if ($failures.Count -gt 0) {
        Write-Error "The provided password does not meet the domain password policy."
        exit 1
    }
}

# -----------------------------------------------------------------------
# Reset password
# -----------------------------------------------------------------------
Write-Host ""
Write-Host "Resetting password for '$Username'..." -ForegroundColor Cyan

try {
    Set-ADAccountPassword -Identity $Username -NewPassword $NewPassword -Reset -ErrorAction Stop

    if ($ForceChangeAtLogon) {
        # PasswordNeverExpires conflicts with ChangePasswordAtLogon
        $adUser = Get-ADUser -Identity $Username -Properties PasswordNeverExpires, DisplayName
        if ($adUser.PasswordNeverExpires) {
            Write-Warning "'PasswordNeverExpires' is enabled on this account. Disabling it so the user can be forced to change their password at next logon."
            Set-ADUser -Identity $Username -PasswordNeverExpires $false -ErrorAction Stop
        }
        Set-ADUser -Identity $Username -ChangePasswordAtLogon $true -ErrorAction Stop
    }

    Write-Host ""
    $displayLabel = if ($adUser.DisplayName) { "$($adUser.DisplayName) ($Username)" } else { $Username }
    Write-Host "    User         : $displayLabel" -ForegroundColor Green
    Write-Host "    Force Change : $ForceChangeAtLogon" -ForegroundColor Green
    Write-Host ""
    Write-Host "Password reset successfully." -ForegroundColor Green

} catch {
    Write-Error "Failed to reset password for '$Username': $_"
    exit 1
}
