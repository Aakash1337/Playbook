<#
.SYNOPSIS
    This script creates a backup of important system directories for CCDC competitions.
    It compresses the selected directories into a timestamped zip file.
#>

param(
    [string]$BackupDestination = "C:\backups"
)

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator to access all files."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`" -BackupDestination '$BackupDestination'"
    Exit
}

# --- Directories to Backup ---
$backupDirs = @(
    "C:\inetpub\wwwroot",
    "C:\Users",
    "C:\ProgramData",
    "C:\Program Files",
    "C:\Program Files (x86)"
)

# --- Create Backup ---
New-Item -ItemType Directory -Force -Path $BackupDestination
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFilename = "ccdc_backup_${timestamp}.zip"
$backupFile = Join-Path $BackupDestination $backupFilename

Write-Host "Backup destination: $BackupDestination"
Write-Host "Backup filename: $backupFilename"

# Filter for directories that exist
$existingDirs = @()
foreach ($dir in $backupDirs) {
    if (Test-Path $dir) {
        $existingDirs += $dir
    } else {
        Write-Warning "Directory $dir does not exist. Skipping."
    }
}

if ($existingDirs.Count -eq 0) {
    Write-Error "No directories to back up. Exiting."
    Exit 1
}

Write-Host "Starting backup of the following directories:"
$existingDirs | ForEach-Object { Write-Host " - $_" }

try {
    Compress-Archive -Path $existingDirs -DestinationPath $backupFile -Force
    Write-Host "Backup successful: $backupFile"
    Get-Item $backupFile | Select-Object Name, Length
} catch {
    Write-Error "Backup failed: $_"
    Exit 1
}

Exit 0
