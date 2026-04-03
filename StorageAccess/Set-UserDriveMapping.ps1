<#
.SYNOPSIS
    Sets the home drive letter and home directory path for an existing AD user.

.DESCRIPTION
    This script updates the HomeDrive and HomeDirectory attributes on an existing
    AD user account. If the target UNC path does not already exist, the script
    will create the directory. The user picker is shown if no username is passed.

.PARAMETER Username
    The SamAccountName of the user to update (e.g. "jsmith").
    If not provided or not found, a numbered list of all AD users is shown.

.PARAMETER DriveLetter
    The drive letter to map (e.g. "H"). Do not include the colon, it will be
    added automatically. If not provided, the script will prompt for one.

.PARAMETER HomePath
    The UNC path to the user's home directory (e.g. "\\fileserver\homes\jsmith").
    If not provided, the script will prompt for one.

.EXAMPLE
    .\Set-UserDriveMapping.ps1

.EXAMPLE
    .\Set-UserDriveMapping.ps1 -Username "jsmith" -DriveLetter "H" -HomePath "\\WIN-DC.mdc.lab\homes\%username%"
#>

#Requires -Modules ActiveDirectory

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [string]$Username,

    [Parameter()]
    [string]$DriveLetter,

    [Parameter()]
    [string]$HomePath
)

# -----------------------------------------------------------------------
# Verify the user exists
# -----------------------------------------------------------------------
Write-Host ""

$adUser = $null

# If a username was passed as a parameter, try it first
if ($Username) {
    $adUser = Get-ADUser -Filter "SamAccountName -eq '$Username'" -Properties DisplayName, HomeDrive, HomeDirectory -ErrorAction SilentlyContinue
    if (-not $adUser) {
        Write-Warning "User '$Username' was not found in Active Directory."
    }
}

# If still not resolved, show a numbered list of all users to pick from
if (-not $adUser) {
    Write-Host "`nRetrieving all AD users..." -ForegroundColor Cyan
    $allUsers = Get-ADUser -Filter * -Properties DisplayName, HomeDrive, HomeDirectory |
                Sort-Object DisplayName

    for ($i = 0; $i -lt $allUsers.Count; $i++) {
        $current = if ($allUsers[$i].HomeDrive) { " - current: $($allUsers[$i].HomeDrive) $($allUsers[$i].HomeDirectory)" } else { '' }
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

# Show the current mapping if one exists
if ($adUser.HomeDrive -or $adUser.HomeDirectory) {
    Write-Host "`n  Current mapping: $($adUser.HomeDrive)  $($adUser.HomeDirectory)" -ForegroundColor Yellow
}

# -----------------------------------------------------------------------
# Drive letter
# -----------------------------------------------------------------------
Write-Host ""

if (-not $DriveLetter) {
    do {
        $DriveLetter = (Read-Host "  Enter drive letter (e.g. H)").Trim().TrimEnd(':').ToUpper()
    } while ($DriveLetter -notmatch '^[A-Z]$')
} else {
    $DriveLetter = $DriveLetter.TrimEnd(':').ToUpper()
    if ($DriveLetter -notmatch '^[A-Z]$') {
        Write-Error "Invalid drive letter '$DriveLetter'. Must be a single letter A-Z."
        exit 1
    }
}

# -----------------------------------------------------------------------
# Home directory path
# -----------------------------------------------------------------------
if (-not $HomePath) {
    do {
        $HomePath = (Read-Host "  Enter UNC home path (e.g. \\fileserver\homes\%username%)").Trim()
    } while ([string]::IsNullOrWhiteSpace($HomePath))
}

# -----------------------------------------------------------------------
# Create the directory if it does not exist
# -----------------------------------------------------------------------

# Resolve %username% to the actual SamAccountName for directory creation
$resolvedPath = $HomePath -replace '%username%', $Username

if (-not (Test-Path -Path $resolvedPath)) {
    Write-Host "`n  Directory '$resolvedPath' does not exist. Creating it..." -ForegroundColor Cyan
    try {
        New-Item -Path $resolvedPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Host "  [Success] Directory created." -ForegroundColor Green
    }
    catch {
        Write-Warning "  Could not create directory '$resolvedPath': $_"
        Write-Warning "  The drive mapping will still be set on the AD account."
    }
} else {
    Write-Host "`n  [Success] Directory already exists." -ForegroundColor Green
}

# -----------------------------------------------------------------------
# Apply the mapping to the AD account
# -----------------------------------------------------------------------
Write-Host "`nApplying drive mapping to $Username..." -ForegroundColor Cyan

try {
    Set-ADUser -Identity $Username -HomeDrive "$($DriveLetter):" -HomeDirectory $HomePath -ErrorAction Stop
    Write-Host "  [Success] Home drive set to $($DriveLetter): -> $HomePath" -ForegroundColor Green
}
catch {
    Write-Host "  [Failed] Could not update AD user: $_" -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  User      : $($adUser.DisplayName) ($Username)" -ForegroundColor Cyan
Write-Host "  Drive     : $($DriveLetter):"                   -ForegroundColor Cyan
Write-Host "  Path      : $HomePath"                          -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
