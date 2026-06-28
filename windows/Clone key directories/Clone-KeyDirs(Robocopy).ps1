<#
Clone-KeyDirs.ps1
Purpose: Clone key directories for baseline/IR. Uses robocopy to preserve timestamps/ACLs where possible,
and writes a manifest + optional hashes.

USAGE EXAMPLES
  # Fast baseline for a web server to a local evidence drive
  .\Clone-KeyDirs.ps1 -Destination "D:\Evidence" -Profile Web -Mode Copy -Hash

  # Mirror (sync) to a network share (be careful with --delete semantics)
  .\Clone-KeyDirs.ps1 -Destination "\\IR-BOX\cases\TEAM10" -Profile Server -Mode Mirror -Hash

  # Minimal "just configs+logs"
  .\Clone-KeyDirs.ps1 -Destination "D:\Evidence" -Profile Minimal -Mode Copy
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$Destination,

  [ValidateSet("Minimal","Workstation","Server","Web","DomainController","Database","Custom")]
  [string]$Profile = "Server",

  [ValidateSet("Copy","Mirror")]
  [string]$Mode = "Copy",

  [switch]$Hash,

  # Only used when Profile=Custom
  [string[]]$CustomPaths = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Sanitize-PathName([string]$p) {
  # Turn C:\Windows\System32 into C__Windows_System32
  return ($p -replace "[:\\\/]", "_").Trim("_")
}

function Ensure-Dir([string]$p) {
  if (-not (Test-Path -LiteralPath $p)) {
    New-Item -ItemType Directory -Path $p | Out-Null
  }
}

if (-not (Test-Admin)) {
  Write-Warning "Not running as Administrator. Some directories/ACLs may fail to copy completely."
}

$now = Get-Date
$runId = "{0}_{1}" -f $env:COMPUTERNAME, $now.ToString("yyyyMMdd_HHmmss")
$rootOut = Join-Path $Destination ("clone_{0}" -f $runId)
Ensure-Dir $rootOut

$logDir = Join-Path $rootOut "logs"
Ensure-Dir $logDir
$mainLog = Join-Path $logDir "robocopy.log"
$metaLog = Join-Path $logDir "metadata.txt"
$manifest = Join-Path $rootOut "manifest.csv"

# Define key directory sets (tune for your environment)
$paths = @()

switch ($Profile) {
  "Minimal" {
    $paths = @(
      "C:\Windows\System32\config",            # registry hives (SYSTEM/SAM/SECURITY/SOFTWARE)
      "C:\Windows\System32\winevt\Logs",       # event logs
      "C:\ProgramData",                       # common persistence + app data
      "C:\Users"                              # user profiles (can be large)
    )
  }
  "Workstation" {
    $paths = @(
      "C:\Windows\System32\config",
      "C:\Windows\System32\winevt\Logs",
      "C:\ProgramData",
      "C:\Users",
      "C:\Windows\Tasks",
      "C:\Windows\System32\Tasks"             # scheduled tasks
    )
  }
  "Server" {
    $paths = @(
      "C:\Windows\System32\config",
      "C:\Windows\System32\winevt\Logs",
      "C:\ProgramData",
      "C:\Users",
      "C:\Windows\System32\Tasks",
      "C:\Windows\Logs"
    )
    if (Test-Path "C:\inetpub") { $paths += "C:\inetpub" }           # IIS content/logs
    if (Test-Path "C:\Apache24") { $paths += "C:\Apache24" }         # Apache
    if (Test-Path "C:\nginx") { $paths += "C:\nginx" }               # Nginx on Windows
    if (Test-Path "C:\Program Files") { $paths += "C:\Program Files" }
    if (Test-Path "C:\Program Files (x86)") { $paths += "C:\Program Files (x86)" }
  }
  "Web" {
    $paths = @(
      "C:\Windows\System32\config",
      "C:\Windows\System32\winevt\Logs",
      "C:\ProgramData",
      "C:\Windows\System32\Tasks",
      "C:\inetpub"
    )
    if (Test-Path "C:\Apache24") { $paths += "C:\Apache24" }
    if (Test-Path "C:\nginx") { $paths += "C:\nginx" }
  }
  "DomainController" {
    $paths = @(
      "C:\Windows\System32\config",
      "C:\Windows\System32\winevt\Logs",
      "C:\Windows\SYSVOL",
      "C:\Windows\System32\Tasks",
      "C:\ProgramData"
    )
    if (Test-Path "C:\Windows\NTDS") { $paths += "C:\Windows\NTDS" } # AD database (can be sensitive/large)
  }
  "Database" {
    $paths = @(
      "C:\Windows\System32\config",
      "C:\Windows\System32\winevt\Logs",
      "C:\ProgramData",
      "C:\Windows\System32\Tasks"
    )
    # Add common DB locations if present
    if (Test-Path "C:\Program Files\Microsoft SQL Server") { $paths += "C:\Program Files\Microsoft SQL Server" }
    if (Test-Path "C:\MySQL") { $paths += "C:\MySQL" }
    if (Test-Path "C:\PostgreSQL") { $paths += "C:\PostgreSQL" }
  }
  "Custom" {
    if ($CustomPaths.Count -eq 0) { throw "Profile=Custom requires -CustomPaths." }
    $paths = $CustomPaths
  }
}

# De-dup + only existing
$paths = $paths | Sort-Object -Unique | Where-Object { Test-Path -LiteralPath $_ }

# Robocopy flags
# /COPY:DATSOU = Data, Attributes, Timestamps, Security(ACL), Owner, Auditing
# /DCOPY:T = preserve directory timestamps
# /XJ = avoid junction loops
# /R:1 /W:1 = fail fast
# /ZB = restartable, fall back to backup mode where possible
$baseArgs = @("/COPY:DATSOU","/DCOPY:T","/XJ","/R:1","/W:1","/ZB","/NP","/TEE","/LOG+:$mainLog")
if ($Mode -eq "Mirror") { $baseArgs = @("/MIR") + $baseArgs } else { $baseArgs = @("/E") + $baseArgs }

# Write metadata
@"
RunId:        $runId
ComputerName: $env:COMPUTERNAME
User:         $env:USERDOMAIN\$env:USERNAME
StartedLocal: $($now.ToString("o"))
Profile:      $Profile
Mode:         $Mode
Destination:  $Destination
Paths:
$($paths -join "`r`n")
"@ | Out-File -FilePath $metaLog -Encoding UTF8

Write-Host "Output root: $rootOut"
Write-Host "Cloning $($paths.Count) paths..."

foreach ($src in $paths) {
  $dstName = Sanitize-PathName $src
  $dst = Join-Path $rootOut $dstName
  Ensure-Dir $dst

  Write-Host "  -> $src  ==>  $dst"
  $args = @($src, $dst) + $baseArgs
  & robocopy @args | Out-Null
}

# Manifest (with optional SHA256)
Write-Host "Generating manifest..."
"RelativePath,SizeBytes,LastWriteTimeUtc,SHA256" | Out-File -FilePath $manifest -Encoding UTF8

$files = Get-ChildItem -LiteralPath $rootOut -Recurse -File -Force | Where-Object { $_.FullName -notlike "$logDir*" }
foreach ($f in $files) {
  $rel = $f.FullName.Substring($rootOut.Length).TrimStart("\")
  $sha = ""
  if ($Hash) {
    try { $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $f.FullName).Hash } catch { $sha = "HASH_ERROR" }
  }
  '"{0}",{1},"{2}","{3}"' -f $rel, $f.Length, $f.LastWriteTimeUtc.ToString("o"), $sha |
    Out-File -FilePath $manifest -Append -Encoding UTF8
}

Write-Host "Done."
Write-Host "Logs:      $logDir"
Write-Host "Manifest:  $manifest"
Write-Host "Metadata:  $metaLog"
