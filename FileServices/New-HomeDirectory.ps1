<#
.SYNOPSIS
    Creates home directories for all members of an Active Directory group.

.DESCRIPTION
    For each member of a specified AD group, this script creates a personal home folder,
    locks it down so only that user, SYSTEM, and Domain Admins can access it, and sets the
    HomeDrive and HomeDirectory attributes on their AD account.

    Users who already have a HomeDirectory set are skipped unless -Force is used.
    A summary table is printed at the end and optionally exported to a CSV report.

.PARAMETER GroupName
    The name of the AD group whose members will be provisioned (e.g. "IT").
    If not provided, a numbered list of AD groups is shown to pick from.

.PARAMETER BasePath
    The base UNC path under which user folders will be created
    (e.g. "\\WIN-DC\homes"). Each user gets a subfolder named after their
    SamAccountName (e.g. "\\WIN-DC\homes\jsmith").

.PARAMETER DriveLetter
    The drive letter to map for each user (e.g. "H"). Do not include the colon,
    it will be added automatically. If not provided, the script will prompt.

.PARAMETER Force
    If specified, users who already have a HomeDirectory set will be rebuilt
    instead of skipped.

.PARAMETER ReportPath
    Optional path to export a CSV report of results
    (e.g. "C:\Reports\HomeDirs.csv"). If not provided, no report is saved.

.EXAMPLE
    .\New-HomeDirectory.ps1

.EXAMPLE
    .\New-HomeDirectory.ps1 -GroupName "IT" -BasePath "\\WIN-DC\homes" -DriveLetter "H"

.EXAMPLE
    .\New-HomeDirectory.ps1 -GroupName "IT" -BasePath "\\WIN-DC\homes" -DriveLetter "H" -Force
#>

#Requires -Modules ActiveDirectory

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [string]$GroupName,

    [Parameter()]
    [string]$BasePath,

    [Parameter()]
    [string]$DriveLetter,

    [switch]$Force,

    [Parameter()]
    [string]$ReportPath
)

# -----------------------------------------------------------------------
# Select group
# -----------------------------------------------------------------------
Write-Host ""

if (-not $GroupName) {
    Write-Host "Retrieving AD groups..." -ForegroundColor Cyan

    # Exclude built-in system groups
    $builtinGroups = @(
        'Access Control Assistance Operators','Account Operators','Administrators',
        'Allowed RODC Password Replication Group','Backup Operators','Cert Publishers',
        'Certificate Service DCOM Access','Cloneable Domain Controllers','Cryptographic Operators',
        'Denied RODC Password Replication Group','Distributed COM Users','DnsUpdateProxy',
        'Domain Admins','Domain Computers','Domain Controllers','Domain Guests','Domain Users',
        'Enterprise Admins','Enterprise Key Admins','Enterprise Read-only Domain Controllers',
        'Event Log Readers','External Trust Accounts','Forest Trust Accounts',
        'Group Policy Creator Owners','Guests','Hyper-V Administrators','IIS_IUSRS',
        'Incoming Forest Trust Builders','Key Admins','Network Configuration Operators',
        'Performance Log Users','Performance Monitor Users','Pre-Windows 2000 Compatible Access',
        'Print Operators','Protected Users','RAS and IAS Servers','RDS Endpoint Servers',
        'RDS Management Servers','RDS Remote Access Servers','Read-only Domain Controllers',
        'Remote Desktop Users','Remote Management Users','Replicator','Schema Admins',
        'Server Operators','Storage Replica Administrators','Terminal Server License Servers',
        'Users','Windows Authorization Access Group'
    )

    $allGroupsFull = Get-ADGroup -Filter * | Sort-Object Name | Select-Object -ExpandProperty Name
    $allGroups     = $allGroupsFull | Where-Object { $builtinGroups -notcontains $_ }

    for ($i = 0; $i -lt $allGroups.Count; $i++) {
        Write-Host "  [$($i + 1)] $($allGroups[$i])"
    }

    # Option to expand to the full list
    $showAll = Read-Host "`n  [A] Show all groups   [Enter] Continue with filtered list"
    if ($showAll -match '^a$') {
        $allGroups = $allGroupsFull
        Write-Host ""
        for ($i = 0; $i -lt $allGroups.Count; $i++) {
            Write-Host "  [$($i + 1)] $($allGroups[$i])"
        }
    }

    do {
        $groupChoice = Read-Host "`nEnter the number of the group"
        $groupIndex  = $groupChoice -as [int]
    } while (-not $groupIndex -or $groupIndex -lt 1 -or $groupIndex -gt $allGroups.Count)

    $GroupName = $allGroups[$groupIndex - 1]
    Write-Host "  Selected: $GroupName" -ForegroundColor Green
}

# Validate the group exists
$adGroup = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
if (-not $adGroup) {
    Write-Error "Group '$GroupName' was not found in Active Directory."
    exit 1
}

# -----------------------------------------------------------------------
# Base path
# -----------------------------------------------------------------------
if (-not $BasePath) {
    do {
        $BasePath = (Read-Host "`n  Enter base UNC path (e.g. \\fileserver\homes)").Trim()
    } while ([string]::IsNullOrWhiteSpace($BasePath))
}

# Strip any trailing backslash
$BasePath = $BasePath.TrimEnd('\')

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
# Get group members
# -----------------------------------------------------------------------
Write-Host "`nRetrieving members of '$GroupName'..." -ForegroundColor Cyan

$members = Get-ADGroupMember -Identity $GroupName -Recursive |
           Where-Object { $_.objectClass -eq 'user' } |
           ForEach-Object { Get-ADUser -Identity $_.SamAccountName -Properties DisplayName, HomeDirectory, HomeDrive }

if ($members.Count -eq 0) {
    Write-Warning "No user members found in '$GroupName'."
    exit 0
}

Write-Host "  Found $($members.Count) user(s).`n" -ForegroundColor Cyan

# -----------------------------------------------------------------------
# Provision each user
# -----------------------------------------------------------------------
$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($user in $members) {

    $sam      = $user.SamAccountName
    $userPath = "$BasePath\$sam"

    # Skip users who already have a home directory set, unless -Force is used
    if ($user.HomeDirectory -and -not $Force) {
        Write-Host "  [Skipped] $sam - already has HomeDirectory set ($($user.HomeDirectory))" -ForegroundColor Yellow
        $results.Add([PSCustomObject]@{
            Username      = $sam
            DisplayName   = $user.DisplayName
            HomeDirectory = $user.HomeDirectory
            Status        = 'Skipped'
            Reason        = 'HomeDirectory already set'
        })
        continue
    }

    try {
        # -- Create the user folder ------------------------------------------
        if (-not (Test-Path -Path $userPath)) {
            New-Item -Path $userPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        # -- Set NTFS permissions --------------------------------------------
        $acl = Get-Acl -Path $userPath

        # Disable inheritance and remove all inherited rules
        $acl.SetAccessRuleProtection($true, $false)

        # Grant the user full control of their own folder
        $userRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sam,
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
        Set-Acl -Path $userPath -AclObject $acl -ErrorAction Stop

        # -- Set AD attributes -----------------------------------------------
        Set-ADUser -Identity $sam -HomeDrive "$($DriveLetter):" -HomeDirectory $userPath -ErrorAction Stop

        Write-Host "  [Success] $sam -> $userPath" -ForegroundColor Green
        $results.Add([PSCustomObject]@{
            Username      = $sam
            DisplayName   = $user.DisplayName
            HomeDirectory = $userPath
            Status        = 'Success'
            Reason        = ''
        })
    }
    catch {
        Write-Host "  [Failed]  $sam - $_" -ForegroundColor Red
        $results.Add([PSCustomObject]@{
            Username      = $sam
            DisplayName   = $user.DisplayName
            HomeDirectory = $userPath
            Status        = 'Failed'
            Reason        = $_.Exception.Message
        })
    }
}

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
$successCount = @($results | Where-Object { $_.Status -eq 'Success' }).Count
$skippedCount = @($results | Where-Object { $_.Status -eq 'Skipped' }).Count
$failCount    = @($results | Where-Object { $_.Status -eq 'Failed'  }).Count

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Group   : $GroupName"                  -ForegroundColor Cyan
Write-Host "  Drive   : $($DriveLetter):"            -ForegroundColor Cyan
Write-Host "  Base    : $BasePath"                   -ForegroundColor Cyan
Write-Host "  Total   : $($members.Count)  |  " -ForegroundColor Cyan -NoNewline
Write-Host "Success : $successCount" -ForegroundColor Green -NoNewline
Write-Host "  |  Skipped : $skippedCount  |  " -ForegroundColor Cyan -NoNewline
if ($failCount -gt 0) {
    Write-Host "Failed : $failCount" -ForegroundColor Red
} else {
    Write-Host "Failed : $failCount" -ForegroundColor Cyan
}
Write-Host "========================================" -ForegroundColor Cyan

$results | Format-Table -AutoSize -Property Username, DisplayName, HomeDirectory, Status, Reason

# -----------------------------------------------------------------------
# Export report
# -----------------------------------------------------------------------
if ($ReportPath) {
    try {
        $results | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "  Report saved to: $ReportPath" -ForegroundColor Cyan
    }
    catch {
        Write-Warning "  Could not save report to '$ReportPath': $_"
    }
}
