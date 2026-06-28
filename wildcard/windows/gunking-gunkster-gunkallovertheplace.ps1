# THE GUNKSTER authored by @Lfgberg - https://lfgberg.org
# This is a script to run hardeningkitty, and similar active tools which can change system configurations

# CONFIGURE ME
$backupDir = "C:\Backups"
$logDir = "C:\Logs"
$backupPath = Join-Path $backupDir "hardening-kitty-backup.csv"
$transcriptPath = Join-Path $logDir "gunking-gunkster.log"

# Create logging directory & start transcript
New-Item -ItemType Directory -Path $logDir
Start-Transcript -Path $transcriptPath

Import-Module ".\HardeningKitty\HardeningKitty.psm1"

# Take a config backup
Invoke-HardeningKitty -Mode Config -Backup -BackupFile $backupPath

# Get all findings list CSV files
$FindingLists = Get-ChildItem -Path ".\HardeningKitty\lists" -Filter "*.csv"

# Loop through each findings list and run Hail Mary mode
foreach ($List in $FindingLists) {
    Write-Host "`n[+] Running HardeningKitty in Hail Mary mode with list: $($List.Name)" -ForegroundColor Cyan
    
    Invoke-HardeningKitty -Mode HailMary -FileFindingList $List.FullName
}

# Persistence Sniper
Install-Module PersistenceSniper
Import-Module PersistenceSniper
Find-AllPersistence