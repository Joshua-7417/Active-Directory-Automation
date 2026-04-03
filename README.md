# Active Directory Automation
PowerShell scripts automating Active Directory tasks including user management, password resets, group assignments, and home directory setup on a Windows Server 2025 domain controller with Windows 11 clients.

## Usage

Download the latest version as a [zip](https://github.com/Joshua-7417/Active-Directory-Automation/archive/refs/heads/main.zip) file or clone the repository.

> [!IMPORTANT]
> All scripts require the [Active Directory](https://learn.microsoft.com/en-us/powershell/module/activedirectory) PowerShell module.

> [!NOTE]
> By default, Windows may block running scripts. You may need to change your execution policy with [Set-ExecutionPolicy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy).

## Scripts

### New-ADUser
Automates the creation of a new Active Directory user account. Creates a new AD user with a standardized username format, assigns them to a specified Organizational Unit (OU), sets an initial password, and optionally adds them to one or more security groups.

<img width="1168" height="704" alt="New-ADUser" src="https://github.com/user-attachments/assets/7d3c762f-07cd-4d3f-aa1c-17026aa02c07"/>


#### Parameters
| Parameter           | Description                                                                                                            |
|---------------------|------------------------------------------------------------------------------------------------------------------------|
| `-FirstName`        | The user's first name.                                                                                                 |
| `-LastName`         | The user's last name.                                                                                                  |
| `-MiddleName`       | The user's middle name. Optional. leave blank to skip.                                                                 |
| `-Department`       | The user's department (e.g. `IT`, `HR`, `Finance`).                                                                    |
| `-Title`            | The user's job title (e.g. `Systems Administrator`).                                                                   |
| `-OU`               | The Distinguished Name of the OU to place the user in (e.g. `OU=Users,OU=IT,DC=mdc,DC=lab`).                           |
| `-Domain`           | The domain suffix used for the UPN and email address (e.g. `mdc.lab`).                                                 |
| `-InitialPassword`  | The temporary password assigned to the account as a SecureString. The user will be forced to change it on first login. |
| `-Groups`           | An optional array of AD group names to add the user to after creation.                                                 |

#### Examples
```powershell
# Run interactively
.\New-ADUser.ps1

# Run with all parameters
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
```

### New-ADUsersFromCSV
Reads a CSV file where each row represents a new user, then creates each account using the same username, display name, and password logic as **New-ADUser**.

<img width="1168" height="704" alt="ADUsersFromCSV" src="https://github.com/user-attachments/assets/3c5a30e6-6ca1-48bf-9803-cf9cf82aeb57"/>


The CSV must have the following columns:
| Column       | Required | Description                                                                                  |
|--------------|----------|----------------------------------------------------------------------------------------------|
| `FirstName`  | Yes      | The user's first name.                                                                       |
| `LastName`   | Yes      | The user's last name.                                                                        |
| `Department` | Yes      | The user's department (e.g. `IT`, `HR`, `Finance`).                                          |
| `Title`      | Yes      | The user's job title (e.g. `Systems Administrator`).                                         |
| `OU`         | Yes      | The Distinguished Name of the OU to place the user in (e.g. `OU=Users,OU=IT,DC=mdc,DC=lab`). |
| `MiddleName` | No       | The user's middle name. Optional, leave blank to skip.                                       |
| `Groups`     | No       | One or more group names separated by a semicolon (e.g. `HR-Users;Shared-Drive-HR`)           |

#### Parameters
| Parameter          | Description |
|--------------------|-------------------------------------------------------------------------------------------------------|
| `-CsvPath`         | Path to the CSV file to import.                                                                       |
| `-Domain`          | The domain suffix used for UPNs and email addresses.                                                  |
| `-SharedPassword`  | A single SecureString password applied to all created accounts.                                       |
| `-PromptPerUser`   | If specified, prompts for a unique password for each user row instead of using a shared password.     |
| `-ReportPath`      | Optional path to export a CSV summary report of results. By default exported to the `Reports` folder. |

#### Examples
```powershell
# Use a shared password for all users
.\New-ADUsersFromCSV.ps1 -CsvPath .\new-hires.csv -Domain "mdc.lab" -SharedPassword (Read-Host "Shared Password" -AsSecureString)

# Prompt for each user's password individually
.\New-ADUsersFromCSV.ps1 -CsvPath .\new-hires.csv -Domain "mdc.lab" -PromptPerUser

# Use a shared password and export a report
.\New-ADUsersFromCSV.ps1 -CsvPath .\new-hires.csv -Domain "mdc.lab" -SharedPassword (Read-Host "Shared Password" -AsSecureString) -ReportPath "C:\Reports\bulk-import.csv"
```

### Set-ADUserPassword
Resets the password for an existing Active Directory user account. Validates the new password against the domain password policy and optionally forces the user to change their password on next login.

<img width="1168" height="704" alt="Set-ADUserPassword" src="https://github.com/user-attachments/assets/53d13102-0eab-4751-8ef8-00fc326aee41"/>

#### Parameters
| Parameter             | Description |
|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `-Username`           | The SamAccountName of the user whose password will be reset (e.g. `jsmith`).                                                            |
| `-Domain`             | The domain to query the password policy from (e.g. `mdc.lab`).                                                                          |
| `-NewPassword`        | The new password as a SecureString. If not provided, the script will prompt for one and validate it against the domain password policy. |
| `-ForceChangeAtLogon` | If specified, the user will be required to change their password on next login. Defaults to `$true`.                                    |

#### Examples
```powershell
# Run interactively
.\Set-ADUserPassword.ps1

.\Set-ADUserPassword.ps1 -Username "jsmith" -Domain "mdc.lab"

.\Set-ADUserPassword.ps1 -Username "jsmith" -Domain "mdc.lab" -ForceChangeAtLogon:$false
```

### Add-ADUserToGroups
Looks up an existing AD user and adds them to one or more specified groups. Each group is validated before attempting to add the user, and a result is reported per group showing success, failure, or whether the user was already a member.

<img width="1168" height="704" alt="ADUserToGroups" src="https://github.com/user-attachments/assets/ab6b2f1a-99f0-4ad8-a500-be704688b3e0"/>

#### Parameters
| Parameter    | Description                                                                                                                              |
|--------------|------------------------------------------------------------------------------------------------------------------------------------------|
| `-Username`  | The SamAccountName of the user to add to groups (e.g. `jsmith`). If not provided or not found, a numbered list of all AD users is shown. |
| `-Groups`    | One or more AD group names to add the user to. If not provided, a numbered list of AD groups is shown for selection.                     |

#### Examples
```powershell
# Run interactively
.\Add-ADUserToGroups.ps1

.\Add-ADUserToGroups.ps1 -Username "jsmith" -Groups "HR-Users", "Shared-Drive-HR"

.\Add-ADUserToGroups.ps1 -Username "jsmith"
```

### New-HomeDirectory
For each member of a specified AD group, creates a personal home folder, locks it down so only that user, SYSTEM, and Domain Admins can access it, and sets the HomeDrive and HomeDirectory attributes on their AD account. Users who already have a HomeDirectory set are skipped unless `-Force` is used.

<img width="1168" height="704" alt="New-HomeDirectory" src="https://github.com/user-attachments/assets/02f7a77c-1de6-43b0-94f0-49fdc5f3584c"/>

#### Parameters
| Parameter      | Description |
|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| `-GroupName`   | The name of the AD group whose members will be set up (e.g. `IT`). If not provided, a numbered list of AD groups is shown.                       |
| `-BasePath`    | The base UNC path under which user folders will be created (e.g. `\\WIN-DC\homes`). Each user gets a subfolder named after their SamAccountName. |
| `-DriveLetter` | The drive letter to map for each user (e.g. `H`). Do not include the colon.                                                                      |
| `-Force`       | If specified, users who already have a HomeDirectory set will be rebuilt instead of skipped.                                                     |
| `-ReportPath`  | Optional path to export a CSV report of results.                                                                                                 |

#### Examples
```powershell
# Run interactively
.\New-HomeDirectory.ps1

.\New-HomeDirectory.ps1 -GroupName "IT" -BasePath "\\WIN-DC\homes" -DriveLetter "H"

.\New-HomeDirectory.ps1 -GroupName "IT" -BasePath "\\WIN-DC\homes" -DriveLetter "H" -Force
```

### Set-HomeDirectoryPermissions
Repairs or reapplies NTFS permissions on a user's home directory. Useful when permissions become broken or need to be corrected without fully rebuilding the user's home drive mapping. Existing inherited permissions are removed and replaced with explicit rules.

<img width="1168" height="704" alt="Set-HomeDirectoryPermissions" src="https://github.com/user-attachments/assets/8dd13822-7beb-4945-b018-c5156aa5c002"/>

The standard permission set applied is:
| Principal      | Permission    |
|----------------|---------------|
| User           | Full Control  |
| SYSTEM         | Full Control  |
| Domain Admins  | Full Control  |

#### Parameters
| Parameter      | Description                                                                                                                                                                       |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-Username`    | The SamAccountName of the user whose folder permissions will be set (e.g. `jsmith`). If not provided or not found, a numbered list is shown.                                      |
| `-FolderPath`  | The full path to the user's home directory folder (e.g. `\\WIN-DC\homes\jsmith`). If not provided, the script will attempt to read it from the user's HomeDirectory AD attribute. |

#### Examples
```powershell
# Run interactively
.\Set-HomeDirectoryPermissions.ps1

.\Set-HomeDirectoryPermissions.ps1 -Username "jsmith"

.\Set-HomeDirectoryPermissions.ps1 -Username "jsmith" -FolderPath "\\WIN-DC\homes\jsmith"
```

### Set-UserDriveMapping
Sets the home drive letter and home directory path for an existing AD user. Updates the HomeDrive and HomeDirectory attributes on an existing AD user account. If the target UNC path does not already exist, the script will create the directory.

<img width="1168" height="704" alt="Set-UserDriveMapping" src="https://github.com/user-attachments/assets/d276376c-d6f2-4d63-b162-0452fe2d319c"/>

#### Parameters
| Parameter      | Description                                                                                                                       |
|----------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `-Username`    | The SamAccountName of the user to update (e.g. `jsmith`). If not provided or not found, a numbered list of all AD users is shown. |
| `-DriveLetter` | The drive letter to map (e.g. `H`). Do not include the colon, it will be added automatically.                                     |
| `-HomePath`    | The UNC path to the user's home directory (e.g. `\\fileserver\homes\%username%`).                                                 |

#### Examples
```powershell
# Run interactively
.\Set-UserDriveMapping.ps1

.\Set-UserDriveMapping.ps1 -Username "jsmith" -DriveLetter "H" -HomePath "\\WIN-DC.mdc.lab\homes\%username%"
```
