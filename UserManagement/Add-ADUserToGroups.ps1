<#
.SYNOPSIS
    Adds an existing Active Directory user to one or more security groups.

.DESCRIPTION
    This script looks up an existing AD user and adds them to one or more
    specified groups. Each group is validated before attempting to add the
    user, and a result is reported per group showing success, failure, or
    whether the user was already a member.

.PARAMETER Username
    The SamAccountName of the user to add to groups (e.g. "jsmith").
    If not provided or not found, a numbered list of all AD users is shown.

.PARAMETER Groups
    One or more AD group names to add the user to.
    If not provided, a numbered list of all AD groups is shown for selection.

.EXAMPLE
    .\Add-ADUserToGroups.ps1

.EXAMPLE
    .\Add-ADUserToGroups.ps1 -Username "jsmith" -Groups "HR-Users", "Shared-Drive-HR"

.EXAMPLE
    .\Add-ADUserToGroups.ps1 -Username "jsmith"
#>

#Requires -Modules ActiveDirectory

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [string]$Username,

    [Parameter()]
    [string[]]$Groups = @()
)

# -----------------------------------------------------------------------
# Verify the user exists
# -----------------------------------------------------------------------
Write-Host ""

$adUser = $null

# If a username was passed as a parameter, try it first
if ($Username) {
    $adUser = Get-ADUser -Filter "SamAccountName -eq '$Username'" -Properties DisplayName, MemberOf -ErrorAction SilentlyContinue
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
# Select groups
# -----------------------------------------------------------------------

# If no groups were passed as a parameter, show a numbered list to pick from
if ($Groups.Count -eq 0) {
    Write-Host "`nRetrieving AD groups..." -ForegroundColor Cyan

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

    # Allow selecting multiple groups by entering comma
    do {
        $groupInput = Read-Host "`nEnter the number(s) of the group(s) to add (e.g. 1,3,5)"
        $groupIndices = $groupInput -split ',' | ForEach-Object { $_.Trim() -as [int] }
        $validIndices = $groupIndices | Where-Object { $_ -ge 1 -and $_ -le $allGroups.Count }
    } while ($validIndices.Count -eq 0)

    $Groups = $validIndices | ForEach-Object { $allGroups[$_ - 1] }
    Write-Host ""
    $Groups | ForEach-Object { Write-Host "  Selected: $_" -ForegroundColor Green }
}

# -----------------------------------------------------------------------
# Add user to groups
# -----------------------------------------------------------------------
Write-Host "`nAdding $Username to $($Groups.Count) group(s)..." -ForegroundColor Cyan

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($group in $Groups) {

    # Validate the group exists
    $adGroup = Get-ADGroup -Filter "Name -eq '$group'" -ErrorAction SilentlyContinue
    if (-not $adGroup) {
        Write-Host "  [Failed] Group '$group' was not found in AD." -ForegroundColor Red
        $results.Add([PSCustomObject]@{
            Group  = $group
            Status = 'Failed'
            Reason = 'Group not found in AD'
        })
        continue
    }

    # Check if the user is already a member
    $isMember = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue |
                Where-Object { $_.SamAccountName -eq $Username }

    if ($isMember) {
        Write-Host "  [Skipped] '$Username' is already a member of '$group'." -ForegroundColor Yellow
        $results.Add([PSCustomObject]@{
            Group  = $group
            Status = 'Already Member'
            Reason = ''
        })
        continue
    }

    # Add the user
    try {
        Add-ADGroupMember -Identity $group -Members $Username -ErrorAction Stop
        Write-Host "  [Success] Added to '$group'" -ForegroundColor Green
        $results.Add([PSCustomObject]@{
            Group  = $group
            Status = 'Success'
            Reason = ''
        })
    }
    catch {
        Write-Host "  [Failed] Could not add to '$group': $_" -ForegroundColor Red
        $results.Add([PSCustomObject]@{
            Group  = $group
            Status = 'Failed'
            Reason = $_.Exception.Message
        })
    }
}

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
$successCount = @($results | Where-Object { $_.Status -eq 'Success'       }).Count
$skippedCount = @($results | Where-Object { $_.Status -eq 'Already Member' }).Count
$failCount    = @($results | Where-Object { $_.Status -eq 'Failed'         }).Count

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  User   : $($adUser.DisplayName) ($Username)" -ForegroundColor Cyan
Write-Host "  Groups : $($Groups.Count)  |  " -ForegroundColor Cyan -NoNewline
Write-Host "Added : $successCount" -ForegroundColor Green -NoNewline
Write-Host "  |  Already Member : $skippedCount  |  " -ForegroundColor Cyan -NoNewline
if ($failCount -gt 0) {
    Write-Host "Failed : $failCount" -ForegroundColor Red
} else {
    Write-Host "Failed : $failCount" -ForegroundColor Cyan
}
Write-Host "========================================" -ForegroundColor Cyan

$results | Format-Table -AutoSize -Property Group, Status, Reason
