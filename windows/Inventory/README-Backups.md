# Backups.ps1

A flexible PowerShell backup utility with compression, rotation, and CCDC-specific defaults for critical Windows system files.

## Features

- **Multiple Backup Modes**: Full, Incremental, or Differential backups
- **CCDC Defaults**: Auto-detects and backs up critical system paths (DNS, AD, IIS, registry, etc.)
- **Compression**: Optimal, Fastest, or NoCompression options
- **Retention Policy**: Automatic cleanup of old backups (configurable days)
- **Integrity Verification**: Optional backup verification after creation
- **Email Notifications**: Send reports via SMTP after backup completion
- **Detailed Logging**: Timestamped logs with statistics

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7+
- Administrator privileges (for system file access)
- Sufficient disk space at destination

## Quick Start

### Basic CCDC Backup
```powershell
.\Backups.ps1 -CCDCDefaults -DestinationRoot "D:\Backups"
```

### Manual Path Backup
```powershell
.\Backups.ps1 -SourcePaths "C:\Users\John\Documents","C:\Projects" -DestinationRoot "D:\Backups"
```

### CCDC Defaults + Custom Paths
```powershell
.\Backups.ps1 -CCDCDefaults -AdditionalPaths "C:\CustomApp\Config" -DestinationRoot "D:\Backups"
```

### Incremental Backup with Verification
```powershell
.\Backups.ps1 -CCDCDefaults -DestinationRoot "\\NAS\Backups" -BackupMode Incremental -Verify
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-SourcePaths` | String[] | Array of paths to backup (files or folders) |
| `-DestinationRoot` | String | **Required.** Root directory for backups |
| `-CCDCDefaults` | Switch | Use predefined CCDC-critical paths |
| `-AdditionalPaths` | String[] | Extra paths when using `-CCDCDefaults` |
| `-BackupMode` | String | `Full`, `Incremental`, or `Differential` (default: Full) |
| `-RetentionDays` | Int | Days to keep old backups (default: 30, 0 = disable) |
| `-CompressionLevel` | String | `Optimal`, `Fastest`, or `NoCompression` |
| `-ExcludePatterns` | String[] | Wildcard patterns to exclude (e.g., `*.tmp`) |
| `-Verify` | Switch | Verify backup integrity after creation |
| `-EmailReport` | Switch | Send email report after completion |
| `-SmtpServer` | String | SMTP server for notifications |
| `-EmailFrom` | String | Sender email address |
| `-EmailTo` | String[] | Recipient email address(es) |

## CCDC Critical Paths (Auto-detected)

The `-CCDCDefaults` switch automatically backs up:

- **System Config**: hosts file, network config, registry hives, scheduled tasks, event logs
- **DNS Server**: Zone files (`%SystemRoot%\System32\dns`)
- **Active Directory**: NTDS database, SYSVOL
- **Web Servers**: IIS, Apache, Nginx configurations and content
- **Databases**: SQL Server, MySQL, PostgreSQL data directories
- **Mail/FTP Servers**: hMailServer, FileZilla Server configs
- **Security**: Certificates, PowerShell profiles, startup folders, firewall logs

## Output

Backups are created in timestamped folders:
```
D:\Backups\
├── Backup_HOSTNAME_20250115_143022_Full.zip
├── Backup_HOSTNAME_20250116_080000_Incremental.zip
└── ...
```

Each backup includes a `backup.log` with detailed statistics.

## Scheduling

Use Windows Task Scheduler for automated backups:
```powershell
# Create a daily backup task
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Scripts\Backups.ps1 -CCDCDefaults -DestinationRoot D:\Backups"
$trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM
Register-ScheduledTask -TaskName "CCDC Daily Backup" -Action $action -Trigger $trigger -RunLevel Highest
```

## Notes

- Run as Administrator for full access to system files
- Network paths (UNC) are supported for destinations
- Default exclusions: `*.tmp`, `*.temp`, `~$*`, `Thumbs.db`, `desktop.ini`
