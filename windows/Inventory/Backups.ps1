<#
.SYNOPSIS
  Flexible file/folder backup script with compression, rotation, and scheduling support.
  Includes CCDC-specific defaults for critical system files.

.DESCRIPTION
  Creates compressed backups of specified paths with:
    - Full/Incremental/Differential backup modes
    - Automatic retention/rotation policies
    - Email notifications (optional)
    - Detailed logging
    - Exclusion patterns
    - Verification and integrity checks
    - CCDC defaults for critical Windows paths

.PARAMETER SourcePaths
  Array of paths to backup (files or folders). Not required if -CCDCDefaults is used.

.PARAMETER DestinationRoot
  Root directory where backups will be stored.

.PARAMETER CCDCDefaults
  Use predefined CCDC-critical paths (web servers, DNS, registry, configs, etc.).
  Automatically detects which services are present on the system.

.PARAMETER AdditionalPaths
  Extra paths to include when using -CCDCDefaults.

.PARAMETER BackupMode
  Type of backup: Full, Incremental, or Differential (default: Full).

.PARAMETER RetentionDays
  Number of days to keep old backups (default: 30). Set to 0 to disable cleanup.

.PARAMETER CompressionLevel
  Compression level: Optimal, Fastest, NoCompression (default: Optimal).

.PARAMETER ExcludePatterns
  Array of wildcard patterns to exclude (e.g., *.tmp, *.log, ~$*).

.PARAMETER Verify
  Verify backup integrity after creation.

.PARAMETER EmailReport
  Send email report after backup completes.

.PARAMETER SmtpServer
  SMTP server for email notifications.

.PARAMETER EmailFrom
  Sender email address.

.PARAMETER EmailTo
  Recipient email address(es).

.PARAMETER EmailSubject
  Custom email subject (default: auto-generated).

.EXAMPLE
  .\Backups.ps1 -CCDCDefaults -DestinationRoot "D:\Backups"
  Backs up all CCDC-critical paths that exist on the system.

.EXAMPLE
  .\Backups.ps1 -CCDCDefaults -AdditionalPaths "C:\CustomApp\Config" -DestinationRoot "D:\Backups"
  CCDC defaults plus custom application config.

.EXAMPLE
  .\Backups.ps1 -SourcePaths "C:\Users\John\Documents","C:\Projects" -DestinationRoot "D:\Backups"
  Manual path specification.

.EXAMPLE
  .\Backups.ps1 -CCDCDefaults -DestinationRoot "\\NAS\Backups" -BackupMode Incremental -Verify
  Incremental CCDC backup with verification.

.NOTES
  Version: 2.0
  Schedule with Task Scheduler for automatic backups.
  Run as Administrator for full access to system files.
#>

[CmdletBinding()]
param(
  [string[]]$SourcePaths,

  [Parameter(Mandatory)]
  [string]$DestinationRoot,

  # CCDC-specific options
  [switch]$CCDCDefaults,

  [string[]]$AdditionalPaths,

  [ValidateSet("Full","Incremental","Differential")]
  [string]$BackupMode = "Full",

  [int]$RetentionDays = 30,

  [ValidateSet("Optimal","Fastest","NoCompression")]
  [string]$CompressionLevel = "Optimal",

  [string[]]$ExcludePatterns = @("*.tmp","*.temp","~$*","Thumbs.db","desktop.ini"),

  [switch]$Verify,

  [switch]$EmailReport,

  [string]$SmtpServer,

  [string]$EmailFrom,

  [string[]]$EmailTo,

  [string]$EmailSubject,

  [switch]$UseSSL,

  [int]$SmtpPort = 587,

  [PSCredential]$SmtpCredential
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Script-level variables
$script:StartTime = Get-Date
$script:LogPath = $null
$script:BackupLog = @()
$script:Stats = @{
  FilesProcessed = 0
  FilesSkipped = 0
  FilesFailed = 0
  BytesProcessed = 0
  BytesSkipped = 0
  Warnings = 0
  Errors = 0
}

# ---------------------------- CCDC Critical Paths ----------------------------

function Get-CCDCCriticalPaths {
  <#
  .SYNOPSIS
    Returns array of CCDC-critical paths that exist on the system.
  #>

  $criticalPaths = @()

  # ===== SYSTEM CONFIGURATION =====
  # Hosts file - attackers love to redirect traffic
  $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
  if (Test-Path $hostsFile) { $criticalPaths += $hostsFile }

  # Network config
  $etcFolder = "$env:SystemRoot\System32\drivers\etc"
  if (Test-Path $etcFolder) { $criticalPaths += $etcFolder }

  # Registry hives (SAM, SECURITY, SYSTEM, SOFTWARE) - credentials & config
  $regConfig = "$env:SystemRoot\System32\config"
  if (Test-Path $regConfig) { $criticalPaths += $regConfig }

  # Scheduled Tasks - persistence mechanism
  $tasks = "$env:SystemRoot\System32\Tasks"
  if (Test-Path $tasks) { $criticalPaths += $tasks }

  # Windows Event Logs - forensics
  $eventLogs = "$env:SystemRoot\System32\winevt\Logs"
  if (Test-Path $eventLogs) { $criticalPaths += $eventLogs }

  # ===== DNS SERVER =====
  $dnsZones = "$env:SystemRoot\System32\dns"
  if (Test-Path $dnsZones) { $criticalPaths += $dnsZones }

  # ===== ACTIVE DIRECTORY (Domain Controllers) =====
  # NTDS database
  $ntds = "$env:SystemRoot\NTDS"
  if (Test-Path $ntds) { $criticalPaths += $ntds }

  # SYSVOL - Group Policy, logon scripts
  $sysvol = "$env:SystemRoot\SYSVOL"
  if (Test-Path $sysvol) { $criticalPaths += $sysvol }

  # ===== WEB SERVERS =====
  # IIS
  $iisRoot = "C:\inetpub"
  if (Test-Path $iisRoot) { $criticalPaths += $iisRoot }

  $iisConfig = "$env:SystemRoot\System32\inetsrv\config"
  if (Test-Path $iisConfig) { $criticalPaths += $iisConfig }

  # Apache (common locations)
  @(
    "C:\Apache24",
    "C:\Apache2",
    "C:\Program Files\Apache Group\Apache2",
    "C:\Program Files (x86)\Apache Group\Apache2",
    "C:\xampp\apache",
    "C:\wamp\bin\apache"
  ) | ForEach-Object {
    if (Test-Path $_) { $criticalPaths += $_ }
  }

  # Nginx (common locations)
  @(
    "C:\nginx",
    "C:\Program Files\nginx"
  ) | ForEach-Object {
    if (Test-Path $_) { $criticalPaths += $_ }
  }

  # ===== DATABASES =====
  # SQL Server (common data locations)
  @(
    "C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\DATA",
    "C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Backup"
  ) | ForEach-Object {
    Get-ChildItem -Path $_ -ErrorAction SilentlyContinue | ForEach-Object {
      $criticalPaths += $_.FullName
    }
  }

  # MySQL (common locations)
  @(
    "C:\ProgramData\MySQL",
    "C:\Program Files\MySQL\MySQL Server*\data",
    "C:\xampp\mysql\data",
    "C:\wamp\bin\mysql\mysql*\data"
  ) | ForEach-Object {
    Get-ChildItem -Path $_ -ErrorAction SilentlyContinue | ForEach-Object {
      $criticalPaths += $_.FullName
    }
  }

  # PostgreSQL
  @(
    "C:\Program Files\PostgreSQL\*\data",
    "C:\ProgramData\PostgreSQL"
  ) | ForEach-Object {
    Get-ChildItem -Path $_ -ErrorAction SilentlyContinue | ForEach-Object {
      $criticalPaths += $_.FullName
    }
  }

  # ===== MAIL SERVERS =====
  # hMailServer
  $hmail = "C:\Program Files (x86)\hMailServer"
  if (Test-Path $hmail) { $criticalPaths += $hmail }

  # ===== FTP SERVERS =====
  # FileZilla Server
  @(
    "C:\Program Files\FileZilla Server",
    "C:\Program Files (x86)\FileZilla Server"
  ) | ForEach-Object {
    if (Test-Path $_) { $criticalPaths += $_ }
  }

  # ===== CERTIFICATES =====
  # Machine certificates store
  $certStore = "C:\ProgramData\Microsoft\Crypto"
  if (Test-Path $certStore) { $criticalPaths += $certStore }

  # ===== POWERSHELL PROFILES (persistence) =====
  @(
    "$env:SystemRoot\System32\WindowsPowerShell\v1.0\profile.ps1",
    "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
    "$env:ProgramFiles\PowerShell\7\profile.ps1"
  ) | ForEach-Object {
    if (Test-Path $_) { $criticalPaths += $_ }
  }

  # ===== STARTUP FOLDERS (persistence) =====
  $startupAll = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
  if (Test-Path $startupAll) { $criticalPaths += $startupAll }

  # ===== FIREWALL RULES =====
  # Export via script at backup time - can't directly copy these
  # We'll back up the SharedAccess folder which has firewall config
  $fwConfig = "$env:SystemRoot\System32\LogFiles\Firewall"
  if (Test-Path $fwConfig) { $criticalPaths += $fwConfig }

  # ===== SERVICES CONFIG =====
  # Windows services are in registry, already backed up via config folder

  return $criticalPaths | Select-Object -Unique
}

# ---------------------------- Helper Functions ----------------------------

function Write-Log {
  param(
    [Parameter(Mandatory)]
    [string]$Message,
    [ValidateSet("INFO","SUCCESS","WARN","ERROR")]
    [string]$Level = "INFO"
  )
  
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $logEntry = "[$timestamp] [$Level] $Message"
  
  # Console output with colors
  $color = switch ($Level) {
    "SUCCESS" { "Green" }
    "WARN"    { "Yellow" }
    "ERROR"   { "Red" }
    default   { "White" }
  }
  
  Write-Host $logEntry -ForegroundColor $color
  
  # File output
  if ($script:LogPath) {
    $logEntry | Out-File -Append -FilePath $script:LogPath -Encoding UTF8
  }
  
  # Add to backup log for reporting
  $script:BackupLog += [pscustomobject]@{
    Timestamp = Get-Date
    Level = $Level
    Message = $Message
  }
  
  if ($Level -eq "WARN") { $script:Stats.Warnings++ }
  if ($Level -eq "ERROR") { $script:Stats.Errors++ }
}

function Initialize-BackupEnvironment {
  param([string]$Root)
  
  try {
    # Create destination root if it doesn't exist
    if (-not (Test-Path $Root)) {
      New-Item -ItemType Directory -Path $Root -Force | Out-Null
      Write-Log "Created backup destination: $Root" -Level "SUCCESS"
    }
    
    # Create timestamped backup folder
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $backupFolder = Join-Path $Root "Backup_${hostname}_${timestamp}_${BackupMode}"
    
    New-Item -ItemType Directory -Path $backupFolder -Force | Out-Null
    
    # Initialize log
    $script:LogPath = Join-Path $backupFolder "backup.log"
    
    return $backupFolder
  } catch {
    Write-Error "Failed to initialize backup environment: $_"
    throw
  }
}

function Get-LastBackupInfo {
  param([string]$Root)
  
  try {
    $backups = Get-ChildItem -Path $Root -Directory | 
      Where-Object { $_.Name -match '^Backup_.*_\d{8}_\d{6}_' } |
      Sort-Object CreationTime -Descending
    
    if ($backups.Count -gt 0) {
      $lastFull = $backups | Where-Object { $_.Name -match '_Full$' } | Select-Object -First 1
      $lastAny = $backups | Select-Object -First 1
      
      return [pscustomobject]@{
        LastFullBackup = $lastFull
        LastBackup = $lastAny
      }
    }
    
    return $null
  } catch {
    Write-Log "Failed to get last backup info: $_" -Level "WARN"
    return $null
  }
}

function Test-ShouldBackupFile {
  param(
    [Parameter(Mandatory)]
    [System.IO.FileInfo]$File,
    [Nullable[datetime]]$BaselineDate
  )
  
  # Check exclusion patterns
  foreach ($pattern in $ExcludePatterns) {
    if ($File.Name -like $pattern) {
      Write-Log "Skipped (excluded): $($File.FullName)" -Level "INFO"
      $script:Stats.FilesSkipped++
      $script:Stats.BytesSkipped += $File.Length
      return $false
    }
  }
  
  # For incremental/differential, check modification date
  if ($BackupMode -ne "Full" -and $BaselineDate) {
    if ($File.LastWriteTime -le $BaselineDate) {
      $script:Stats.FilesSkipped++
      $script:Stats.BytesSkipped += $File.Length
      return $false
    }
  }
  
  return $true
}

function Copy-FileWithMetadata {
  param(
    [Parameter(Mandatory)]
    [string]$SourcePath,
    [Parameter(Mandatory)]
    [string]$DestinationPath
  )
  
  try {
    # Ensure destination directory exists
    $destDir = Split-Path -Parent $DestinationPath
    if (-not (Test-Path $destDir)) {
      New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }
    
    # Copy file preserving timestamps
    Copy-Item -Path $SourcePath -Destination $DestinationPath -Force
    
    # Preserve timestamps
    $sourceFile = Get-Item $SourcePath
    $destFile = Get-Item $DestinationPath
    $destFile.CreationTime = $sourceFile.CreationTime
    $destFile.LastWriteTime = $sourceFile.LastWriteTime
    $destFile.LastAccessTime = $sourceFile.LastAccessTime
    
    $script:Stats.FilesProcessed++
    $script:Stats.BytesProcessed += $sourceFile.Length
    
    return $true
  } catch {
    Write-Log "Failed to copy file $SourcePath : $_" -Level "ERROR"
    $script:Stats.FilesFailed++
    return $false
  }
}

function Backup-Path {
  param(
    [Parameter(Mandatory)]
    [string]$SourcePath,
    [Parameter(Mandatory)]
    [string]$DestinationFolder,
    [Nullable[datetime]]$BaselineDate
  )
  
  Write-Log "Processing: $SourcePath"
  
  if (-not (Test-Path $SourcePath)) {
    Write-Log "Source path not found: $SourcePath" -Level "ERROR"
    return
  }
  
  $item = Get-Item $SourcePath
  
  # Build params for Test-ShouldBackupFile
  $testParams = @{ File = $null }
  if ($BaselineDate) { $testParams.BaselineDate = $BaselineDate }

  if ($item.PSIsContainer) {
    # Directory - process recursively
    $files = Get-ChildItem -Path $SourcePath -Recurse -File -ErrorAction SilentlyContinue

    foreach ($file in $files) {
      $testParams.File = $file
      if (Test-ShouldBackupFile @testParams) {
        $relativePath = $file.FullName.Substring($SourcePath.Length).TrimStart('\')
        $destPath = Join-Path $DestinationFolder (Split-Path -Leaf $SourcePath)
        $destPath = Join-Path $destPath $relativePath

        $null = Copy-FileWithMetadata -SourcePath $file.FullName -DestinationPath $destPath
      }
    }
  } else {
    # Single file
    $testParams.File = $item
    if (Test-ShouldBackupFile @testParams) {
      $destPath = Join-Path $DestinationFolder $item.Name
      $null = Copy-FileWithMetadata -SourcePath $item.FullName -DestinationPath $destPath
    }
  }
}

function Compress-Backup {
  param(
    [Parameter(Mandatory)]
    [string]$BackupFolder
  )
  
  Write-Log "Compressing backup..."
  
  try {
    $zipPath = "$BackupFolder.zip"
    
    $compressionParam = switch ($CompressionLevel) {
      "Optimal" { [System.IO.Compression.CompressionLevel]::Optimal }
      "Fastest" { [System.IO.Compression.CompressionLevel]::Fastest }
      "NoCompression" { [System.IO.Compression.CompressionLevel]::NoCompression }
    }
    
    Add-Type -Assembly "System.IO.Compression.FileSystem"
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
      $BackupFolder, 
      $zipPath, 
      $compressionParam, 
      $false
    )
    
    $zipSize = (Get-Item $zipPath).Length
    $originalSize = (Get-ChildItem $BackupFolder -Recurse -File | Measure-Object -Property Length -Sum).Sum
    $ratio = [math]::Round((1 - ($zipSize / $originalSize)) * 100, 2)
    
    Write-Log "Compressed backup created: $zipPath" -Level "SUCCESS"
    Write-Log "Compression ratio: $ratio% (Original: $([math]::Round($originalSize/1MB,2))MB → Compressed: $([math]::Round($zipSize/1MB,2))MB)"
    
    # Remove uncompressed folder
    Remove-Item -Path $BackupFolder -Recurse -Force
    
    return $zipPath
  } catch {
    Write-Log "Compression failed: $_" -Level "ERROR"
    return $BackupFolder
  }
}

function Test-BackupIntegrity {
  param([string]$BackupPath)
  
  Write-Log "Verifying backup integrity..."
  
  try {
    if ($BackupPath -match '\.zip$') {
      # Verify ZIP archive
      Add-Type -Assembly "System.IO.Compression.FileSystem"
      $zip = [System.IO.Compression.ZipFile]::OpenRead($BackupPath)
      $entryCount = $zip.Entries.Count
      $zip.Dispose()
      
      Write-Log "ZIP verification passed: $entryCount entries" -Level "SUCCESS"
      return $true
    } else {
      # Verify folder
      $fileCount = (Get-ChildItem $BackupPath -Recurse -File).Count
      Write-Log "Folder verification passed: $fileCount files" -Level "SUCCESS"
      return $true
    }
  } catch {
    Write-Log "Verification failed: $_" -Level "ERROR"
    return $false
  }
}

function Remove-OldBackups {
  param(
    [string]$Root,
    [int]$Days
  )
  
  if ($Days -le 0) {
    Write-Log "Retention policy disabled (RetentionDays = 0)"
    return
  }
  
  Write-Log "Cleaning up backups older than $Days days..."
  
  try {
    $cutoffDate = (Get-Date).AddDays(-$Days)
    $oldBackups = Get-ChildItem -Path $Root | 
      Where-Object { 
        ($_.Name -match '^Backup_.*_\d{8}_\d{6}') -and 
        ($_.CreationTime -lt $cutoffDate) 
      }
    
    $removedCount = 0
    $freedSpace = 0
    
    foreach ($backup in $oldBackups) {
      $size = if ($backup.PSIsContainer) {
        (Get-ChildItem $backup.FullName -Recurse -File | Measure-Object -Property Length -Sum).Sum
      } else {
        $backup.Length
      }
      
      Remove-Item -Path $backup.FullName -Recurse -Force
      $removedCount++
      $freedSpace += $size
      
      Write-Log "Removed old backup: $($backup.Name)"
    }
    
    if ($removedCount -gt 0) {
      Write-Log "Cleanup complete: Removed $removedCount backup(s), freed $([math]::Round($freedSpace/1MB,2))MB" -Level "SUCCESS"
    } else {
      Write-Log "No old backups to remove"
    }
  } catch {
    Write-Log "Cleanup failed: $_" -Level "WARN"
  }
}

function Send-EmailNotification {
  param([string]$BackupPath)
  
  if (-not $EmailReport) { return }
  
  Write-Log "Sending email notification..."
  
  try {
    $duration = [math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 2)
    $status = if ($script:Stats.Errors -gt 0) { "[!] COMPLETED WITH ERRORS" } else { "[OK] SUCCESS" }
    
    $subject = if ($EmailSubject) { 
      $EmailSubject 
    } else { 
      "Backup Report: $env:COMPUTERNAME - $status"
    }
    
    $body = @"
<html>
<head>
<style>
  body { font-family: Arial, sans-serif; }
  table { border-collapse: collapse; width: 100%; margin: 20px 0; }
  th { background-color: #4CAF50; color: white; padding: 10px; text-align: left; }
  td { padding: 8px; border-bottom: 1px solid #ddd; }
  .success { color: green; font-weight: bold; }
  .error { color: red; font-weight: bold; }
  .warn { color: orange; font-weight: bold; }
</style>
</head>
<body>
<h2>Backup Report - $env:COMPUTERNAME</h2>
<p><b>Status:</b> <span class='$(if($script:Stats.Errors -gt 0){"error"}else{"success"})'>$status</span></p>
<p><b>Mode:</b> $BackupMode</p>
<p><b>Started:</b> $($script:StartTime.ToString("yyyy-MM-dd HH:mm:ss"))</p>
<p><b>Duration:</b> $duration minutes</p>

<h3>Statistics</h3>
<table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Files Processed</td><td>$($script:Stats.FilesProcessed)</td></tr>
  <tr><td>Files Skipped</td><td>$($script:Stats.FilesSkipped)</td></tr>
  <tr><td>Files Failed</td><td class='$(if($script:Stats.FilesFailed -gt 0){"error"}else{""})'>$($script:Stats.FilesFailed)</td></tr>
  <tr><td>Data Processed</td><td>$([math]::Round($script:Stats.BytesProcessed/1MB,2)) MB</td></tr>
  <tr><td>Data Skipped</td><td>$([math]::Round($script:Stats.BytesSkipped/1MB,2)) MB</td></tr>
  <tr><td>Warnings</td><td class='$(if($script:Stats.Warnings -gt 0){"warn"}else{""})'>$($script:Stats.Warnings)</td></tr>
  <tr><td>Errors</td><td class='$(if($script:Stats.Errors -gt 0){"error"}else{""})'>$($script:Stats.Errors)</td></tr>
</table>

<h3>Backup Location</h3>
<p>$BackupPath</p>

<h3>Source Paths</h3>
<ul>
$(foreach($path in $SourcePaths){"<li>$path</li>"})
</ul>

<hr>
<p style='font-size: 0.9em; color: #666;'>Generated by Backup-Files.ps1 v1.0</p>
</body>
</html>
"@

    $mailParams = @{
      From = $EmailFrom
      To = $EmailTo
      Subject = $subject
      Body = $body
      BodyAsHtml = $true
      SmtpServer = $SmtpServer
      Port = $SmtpPort
      UseSsl = $UseSSL
    }
    
    if ($SmtpCredential) {
      $mailParams.Credential = $SmtpCredential
    }
    
    Send-MailMessage @mailParams
    
    Write-Log "Email sent successfully" -Level "SUCCESS"
  } catch {
    Write-Log "Failed to send email: $_" -Level "ERROR"
  }
}

function Show-Summary {
  param([string]$BackupPath, [double]$Duration)
  
  Write-Host ""
  Write-Host "========================================" -ForegroundColor Cyan
  Write-Host "  Backup Complete!" -ForegroundColor Cyan
  Write-Host "========================================" -ForegroundColor Cyan
  Write-Host ""
  Write-Host "Mode:             " -NoNewline
  Write-Host $BackupMode -ForegroundColor Yellow
  Write-Host "Backup Location:  " -NoNewline
  Write-Host $BackupPath -ForegroundColor Cyan
  Write-Host "Duration:         " -NoNewline
  Write-Host "$([math]::Round($Duration,2)) minutes" -ForegroundColor Yellow
  Write-Host ""
  Write-Host "Files Processed:  " -NoNewline
  Write-Host $script:Stats.FilesProcessed -ForegroundColor Green
  Write-Host "Files Skipped:    " -NoNewline
  Write-Host $script:Stats.FilesSkipped -ForegroundColor Gray
  Write-Host "Files Failed:     " -NoNewline
  Write-Host $script:Stats.FilesFailed -ForegroundColor $(if($script:Stats.FilesFailed -gt 0){"Red"}else{"Green"})
  Write-Host "Data Processed:   " -NoNewline
  Write-Host "$([math]::Round($script:Stats.BytesProcessed/1MB,2)) MB" -ForegroundColor Green
  Write-Host "Data Skipped:     " -NoNewline
  Write-Host "$([math]::Round($script:Stats.BytesSkipped/1MB,2)) MB" -ForegroundColor Gray
  Write-Host ""
  Write-Host "Warnings:         " -NoNewline
  Write-Host $script:Stats.Warnings -ForegroundColor $(if($script:Stats.Warnings -gt 0){"Yellow"}else{"Green"})
  Write-Host "Errors:           " -NoNewline
  Write-Host $script:Stats.Errors -ForegroundColor $(if($script:Stats.Errors -gt 0){"Red"}else{"Green"})
  Write-Host ""
}

# ---------------------------- Main Execution ----------------------------

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CCDC Backup Utility v2.0" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Resolve source paths
if ($CCDCDefaults) {
  Write-Host "Using CCDC default paths..." -ForegroundColor Yellow
  $ccdcPaths = Get-CCDCCriticalPaths

  if ($ccdcPaths.Count -eq 0) {
    Write-Host "WARNING: No CCDC-critical paths found on this system!" -ForegroundColor Red
  } else {
    Write-Host "Found $($ccdcPaths.Count) CCDC-critical paths:" -ForegroundColor Green
    $ccdcPaths | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
  }

  # Combine CCDC paths with any additional paths
  $SourcePaths = @($ccdcPaths)
  if ($AdditionalPaths) {
    $SourcePaths += $AdditionalPaths
    Write-Host "Added $($AdditionalPaths.Count) additional path(s)" -ForegroundColor Yellow
  }

  Write-Host ""
}

# Validate we have paths to backup
if (-not $SourcePaths -or $SourcePaths.Count -eq 0) {
  Write-Host "ERROR: No source paths specified." -ForegroundColor Red
  Write-Host "Use -SourcePaths to specify paths, or -CCDCDefaults for CCDC-critical paths." -ForegroundColor Yellow
  exit 1
}

try {
  # Initialize
  $backupFolder = Initialize-BackupEnvironment -Root $DestinationRoot
  Write-Log "Backup started: $BackupMode mode" -Level "SUCCESS"
  Write-Log "Destination: $backupFolder"
  if ($CCDCDefaults) { Write-Log "Using CCDC defaults" }
  
  # Get baseline for incremental/differential
  $baselineDate = $null
  if ($BackupMode -ne "Full") {
    $lastBackup = Get-LastBackupInfo -Root $DestinationRoot
    
    if ($BackupMode -eq "Incremental" -and $lastBackup.LastBackup) {
      $baselineDate = $lastBackup.LastBackup.CreationTime
      Write-Log "Incremental backup - baseline: $($lastBackup.LastBackup.Name)"
    } elseif ($BackupMode -eq "Differential" -and $lastBackup.LastFullBackup) {
      $baselineDate = $lastBackup.LastFullBackup.CreationTime
      Write-Log "Differential backup - baseline: $($lastBackup.LastFullBackup.Name)"
    } else {
      Write-Log "No baseline found, performing Full backup" -Level "WARN"
      $BackupMode = "Full"
    }
  }
  
  # Backup each source path
  Write-Log "Processing $($SourcePaths.Count) source path(s)..."
  foreach ($sourcePath in $SourcePaths) {
    if ($baselineDate) {
      Backup-Path -SourcePath $sourcePath -DestinationFolder $backupFolder -BaselineDate $baselineDate
    } else {
      Backup-Path -SourcePath $sourcePath -DestinationFolder $backupFolder
    }
  }
  
  # Compress if requested
  if ($CompressionLevel -ne "NoCompression") {
    $backupFolder = Compress-Backup -BackupFolder $backupFolder
  }
  
  # Verify integrity
  if ($Verify) {
    $verified = Test-BackupIntegrity -BackupPath $backupFolder
    if (-not $verified) {
      Write-Log "Backup verification failed!" -Level "ERROR"
    }
  }
  
  # Cleanup old backups
  Remove-OldBackups -Root $DestinationRoot -Days $RetentionDays
  
  # Calculate duration
  $duration = ((Get-Date) - $script:StartTime).TotalMinutes
  
  Write-Log "Backup completed successfully" -Level "SUCCESS"
  
  # Send email notification
  if ($EmailReport) {
    Send-EmailNotification -BackupPath $backupFolder
  }
  
  # Show summary
  Show-Summary -BackupPath $backupFolder -Duration $duration
  
} catch {
  Write-Log "Backup failed: $_" -Level "ERROR"
  Write-Host ""
  Write-Host "BACKUP FAILED" -ForegroundColor Red
  Write-Host $_.Exception.Message -ForegroundColor Red
  exit 1
}
