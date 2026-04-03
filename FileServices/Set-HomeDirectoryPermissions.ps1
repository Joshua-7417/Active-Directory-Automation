<#
.SYNOPSIS
    Repairs or reapplies NTFS permissions on a user's home directory.

.DESCRIPTION
    This script reapplies the standard NTFS permission set to a user's home
    directory folder. It is useful when permissions become broken or need to be
    corrected without fully rebuilding the user's home drive mapping.

    The standard permission set applied is:
      - User:          Full Control (no inheritance from parent)
      - SYSTEM:        Full Control
      - Domain Admins: Full Control

    Existing inherited permissions are removed and replaced with explicit rules.

.PARAMETER Username
    The SamAccountName of the user whose folder permissions will be set
    (e.g. "jsmith"). If not provided or not found, a numbered list is shown.

.PARAMETER FolderPath
    The full path to the user's home directory folder
    (e.g. "\\WIN-DC\homes\jsmith"). If not provided, the script will
    attempt to read it from the user's HomeDirectory AD attribute, and
    prompt if that is also empty.

.EXAMPLE
    .\Set-HomeDirectoryPermissions.ps1

.EXAMPLE
    .\Set-HomeDirectoryPermissions.ps1 -Username "jsmith"

.EXAMPLE
    .\Set-HomeDirectoryPermissions.ps1 -Username "jsmith" -FolderPath "\\WIN-DC\homes\jsmith"
#>

#Requires -Modules ActiveDirectory

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [string]$Username,

    [Parameter()]
    [string]$FolderPath
)

# -----------------------------------------------------------------------
# Verify the user exists
# -----------------------------------------------------------------------
Write-Host ""

$adUser = $null

# If a username was passed as a parameter, try it first
if ($Username) {
    $adUser = Get-ADUser -Filter "SamAccountName -eq '$Username'" -Properties DisplayName, HomeDirectory -ErrorAction SilentlyContinue
    if (-not $adUser) {
        Write-Warning "User '$Username' was not found in Active Directory."
    }
}

# If still not resolved, show a numbered list of all users to pick from
if (-not $adUser) {
    Write-Host "`nRetrieving all AD users..." -ForegroundColor Cyan
    $allUsers = Get-ADUser -Filter * -Properties DisplayName, HomeDirectory |
                Sort-Object DisplayName

    for ($i = 0; $i -lt $allUsers.Count; $i++) {
        $current = if ($allUsers[$i].HomeDirectory) { " - $($allUsers[$i].HomeDirectory)" } else { '' }
        Write-Host "  [$($i + 1)] $($allUsers[$i].DisplayName) ($($allUsers[$i].SamAccountName))$current"
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
# Resolve the folder path
# -----------------------------------------------------------------------

# Use the AD HomeDirectory attribute if no path was passed
if (-not $FolderPath -and $adUser.HomeDirectory) {
    # Resolve %username% in case the attribute uses the variable form
    $FolderPath = $adUser.HomeDirectory -replace '%username%', $Username
    Write-Host "`n  Using HomeDirectory from AD: $FolderPath" -ForegroundColor Cyan
}

# If still empty, prompt for it
if (-not $FolderPath) {
    do {
        $FolderPath = (Read-Host "`n  Enter the full path to the user's home folder").Trim()
    } while ([string]::IsNullOrWhiteSpace($FolderPath))
}

# Verify the folder actually exists before touching permissions
if (-not (Test-Path -Path $FolderPath)) {
    Write-Error "Folder '$FolderPath' does not exist. Cannot set permissions."
    exit 1
}

# -----------------------------------------------------------------------
# Apply NTFS permissions
# -----------------------------------------------------------------------
Write-Host "`nApplying NTFS permissions on '$FolderPath'..." -ForegroundColor Cyan

try {
    $acl = Get-Acl -Path $FolderPath

    # Disable inheritance and remove all inherited rules, starting clean
    $acl.SetAccessRuleProtection($true, $false)

    # Remove any existing explicit rules so we apply a known-good set
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

    # Grant the user full control of their own folder
    $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Username,
        'FullControl',
        'ContainerInherit,ObjectInherit',
        'None',
        'Allow'
    )

    # Ensure SYSTEM has full control
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'SYSTEM',
        'FullControl',
        'ContainerInherit,ObjectInherit',
        'None',
        'Allow'
    )

    # Ensure Domain Admins retain full control
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'Domain Admins',
        'FullControl',
        'ContainerInherit,ObjectInherit',
        'None',
        'Allow'
    )

    $acl.AddAccessRule($userRule)
    $acl.AddAccessRule($systemRule)
    $acl.AddAccessRule($adminRule)

    Set-Acl -Path $FolderPath -AclObject $acl -ErrorAction Stop

    Write-Host "  [Success] Permissions applied." -ForegroundColor Green
}
catch {
    Write-Host "  [Failed] Could not set permissions: $_" -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  User   : $($adUser.DisplayName) ($Username)" -ForegroundColor Cyan
Write-Host "  Folder : $FolderPath"                        -ForegroundColor Cyan
Write-Host "  Rules  : $Username, SYSTEM, Domain Admins - Full Control" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
