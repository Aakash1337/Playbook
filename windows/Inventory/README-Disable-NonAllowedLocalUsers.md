# Disable-NonAllowedLocalUsers.ps1

A PowerShell script for auditing and disabling local user accounts not on an allow-list. Designed for CCDC competitions to quickly lock down systems.

## Features

- **Three Operating Modes**: Audit (default), DryRun, and Enforce
- **Anti-Lockout Protection**: Never disables the currently logged-in user
- **Protected Accounts**: Built-in protection for Administrator (customizable)
- **Rollback Support**: Re-enable accounts disabled by a previous run
- **Full Audit Trail**: CSV exports of before/after states and all actions
- **PowerShell Native**: Supports `-WhatIf` and `-Confirm` parameters

## Requirements

- Windows 10+ / Windows Server 2016+
- PowerShell 5.1+ with LocalAccounts module
- Administrator privileges

## Quick Start

### Audit Only (Default - No Changes)
```powershell
.\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash")
```

### Dry Run (Preview Changes)
```powershell
.\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash") -DryRun
```

### Enforce (Actually Disable Accounts)
```powershell
.\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash") -Enforce
```

### Enforce with Confirmation Prompts
```powershell
.\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash") -Enforce -Confirm
```

### Rollback (Re-enable Disabled Accounts)
```powershell
.\Disable-NonAllowedLocalUsers.ps1 -Rollback "C:\ProgramData\CCDC\UserControl\actions_20250115_143022.csv"
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-AllowedUsers` | String[] | **Required.** Users that should remain enabled |
| `-Enforce` | Switch | Actually disable accounts (default is audit-only) |
| `-DryRun` | Switch | Show what would happen without making changes |
| `-Rollback` | String | Path to previous actions CSV to restore accounts |
| `-OverrideProtections` | Switch | Allow disabling protected accounts (dangerous!) |
| `-ProtectedUsers` | String[] | Extra accounts to protect (default: Administrator) |
| `-OutDir` | String | Output folder for logs (default: `C:\ProgramData\CCDC\UserControl`) |

## Operating Modes

| Mode | Description |
|------|-------------|
| **Audit** | Default. Lists what would change, makes no modifications |
| **DryRun** | Explicitly preview changes with detailed output |
| **Enforce** | Actually disables accounts not in the allow-list |
| **Rollback** | Re-enables accounts from a previous enforcement run |

## Safety Features

1. **Anti-Lockout**: The current logged-in user is always protected
2. **Protected Accounts**: Administrator is protected by default
3. **Service Account Detection**: Warns when running as SYSTEM
4. **Confirmation Support**: Use `-Confirm` for per-account prompts
5. **WhatIf Support**: Use `-WhatIf` for PowerShell native preview

## Output Files

All files are saved to `C:\ProgramData\CCDC\UserControl\` (or custom `-OutDir`):

| File | Description |
|------|-------------|
| `disable_users_TIMESTAMP.log` | Detailed execution log |
| `local_users_before_TIMESTAMP.csv` | User inventory before changes |
| `local_users_after_TIMESTAMP.csv` | User inventory after changes |
| `actions_TIMESTAMP.csv` | Record of all actions taken |

## Return Object

The script returns a structured object for automation:

```powershell
@{
    Success       = $true/$false
    DisabledCount = 5
    FailedCount   = 0
    AuditedCount  = 12
    LogFile       = "C:\ProgramData\CCDC\UserControl\disable_users_20250115_143022.log"
    ActionsCsv    = "C:\ProgramData\CCDC\UserControl\actions_20250115_143022.csv"
}
```

## Example Workflow

```powershell
# 1. First, audit to see what would happen
.\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","ScoreBot")

# 2. Review the output, then enforce
.\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","ScoreBot") -Enforce

# 3. If something goes wrong, rollback
.\Disable-NonAllowedLocalUsers.ps1 -Rollback "C:\ProgramData\CCDC\UserControl\actions_20250115_143022.csv"
```

## Warning

Using `-OverrideProtections` can disable the Administrator account and other protected accounts. This is **not recommended** and may lock you out of the system. Use with extreme caution.
