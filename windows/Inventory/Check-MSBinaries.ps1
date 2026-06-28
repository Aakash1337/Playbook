<# 
.SYNOPSIS
  Check Microsoft Windows binaries against known-good hashes (baseline) + signature status.

.DESCRIPTION
  This script helps detect tampered or replaced Windows system binaries by:
  - Creating a baseline of file hashes and signatures from a known-good system
  - Verifying target systems against that baseline
  - Detecting new/unexpected files in monitored directories

.USAGE
  # 1) On a known-good host (same build/patch level):
  .\Check-MSBinaries.ps1 -Mode Baseline -OutFile .\baseline.csv

  # 2) On the target host:
  .\Check-MSBinaries.ps1 -Mode Verify -BaselineFile .\baseline.csv -OutFile .\report.csv

  # Optional: broaden scope (slower)
  .\Check-MSBinaries.ps1 -Mode Baseline -Paths "C:\Windows\System32","C:\Windows\SysWOW64" -Recurse -OutFile .\baseline.csv

  # Include non-Microsoft signed files in baseline
  .\Check-MSBinaries.ps1 -Mode Baseline -IncludeAll -OutFile .\baseline_all.csv

.NOTES
  Version: 2.0
  Requires: PowerShell 5.1+
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet("Baseline", "Verify")]
  [string]$Mode,

  [string]$OutFile = ".\report.csv",

  # Verify mode
  [string]$BaselineFile,

  # Optional scan scope (if omitted: critical list)
  [string[]]$Paths,

  [switch]$Recurse,

  [ValidateSet("SHA256", "SHA1")]
  [string]$HashAlg = "SHA256",

  # Include non-Microsoft signed files in baseline
  [switch]$IncludeAll,

  # In Verify mode, also scan for new/unexpected files
  [switch]$DetectNewFiles
)

# Store hash algorithm at script scope for consistent access
$script:HashAlgorithm = $HashAlg

function Get-FileMeta {
  param(
    [Parameter(Mandatory)]
    [string]$Path,
    
    [string]$Algorithm = $script:HashAlgorithm
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    return [pscustomobject]@{
      Path          = $Path
      Exists        = $false
      Hash          = $null
      HashAlg       = $Algorithm
      SigStatus     = $null
      Signer        = $null
      FileVersion   = $null
      Product       = $null
      Company       = $null
      Length        = $null
      LastWriteTime = $null
    }
  }

  try {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop

    # Hash
    $h = (Get-FileHash -LiteralPath $Path -Algorithm $Algorithm -ErrorAction Stop).Hash

    # Authenticode (handles many catalog-signed files as well)
    $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
    $sigStatus = if ($sig) { $sig.Status.ToString() } else { "Unknown" }
    $signer = $null
    if ($sig -and $sig.SignerCertificate) { 
      $signer = $sig.SignerCertificate.Subject 
    }

    # Version info
    $vi = $item.VersionInfo

    [pscustomobject]@{
      Path          = $Path
      Exists        = $true
      Hash          = $h
      HashAlg       = $Algorithm
      SigStatus     = $sigStatus
      Signer        = $signer
      FileVersion   = $vi.FileVersion
      Product       = $vi.ProductName
      Company       = $vi.CompanyName
      Length        = $item.Length
      LastWriteTime = $item.LastWriteTimeUtc
    }
  }
  catch {
    Write-Warning "Failed to process file '$Path': $_"
    [pscustomobject]@{
      Path          = $Path
      Exists        = $true
      Hash          = "ERROR"
      HashAlg       = $Algorithm
      SigStatus     = "ERROR"
      Signer        = $null
      FileVersion   = $null
      Product       = $null
      Company       = $null
      Length        = $null
      LastWriteTime = $null
    }
  }
}

function Get-CriticalPaths {
  $sys = $env:WINDIR
  @(
    "$sys\System32\lsass.exe",
    "$sys\System32\winlogon.exe",
    "$sys\System32\services.exe",
    "$sys\System32\svchost.exe",
    "$sys\System32\csrss.exe",
    "$sys\System32\smss.exe",
    "$sys\System32\wininit.exe",
    "$sys\System32\explorer.exe",
    "$sys\System32\taskmgr.exe",
    "$sys\System32\cmd.exe",
    "$sys\System32\WindowsPowerShell\v1.0\powershell.exe",
    "$sys\System32\wbem\WmiPrvSE.exe",
    "$sys\System32\conhost.exe",
    "$sys\System32\rundll32.exe",
    "$sys\System32\reg.exe",
    "$sys\System32\wevtutil.exe",
    "$sys\System32\sc.exe",
    "$sys\System32\net.exe",
    "$sys\System32\net1.exe",
    "$sys\System32\whoami.exe",
    "$sys\System32\drivers\ntfs.sys",
    "$sys\System32\drivers\tcpip.sys",
    "$sys\System32\drivers\afd.sys"
  )
}

function Resolve-ScanTargets {
  param(
    [string[]]$Paths, 
    [switch]$Recurse
  )

  if (-not $Paths -or $Paths.Count -eq 0) {
    return Get-CriticalPaths
  }

  $ext = @("*.exe", "*.dll", "*.sys")
  $items = foreach ($p in $Paths) {
    if (Test-Path -LiteralPath $p -PathType Container) {
      Get-ChildItem -LiteralPath $p -Include $ext -File -Force -ErrorAction SilentlyContinue -Recurse:$Recurse
    }
    elseif (Test-Path -LiteralPath $p -PathType Leaf) {
      Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    }
  }
  $items | ForEach-Object { $_.FullName } | Select-Object -Unique
}

function Get-OSContext {
  # Get OS information with fallback for systems without Get-ComputerInfo
  $osInfo = [pscustomobject]@{
    WindowsProductName          = "Unknown"
    WindowsVersion              = "Unknown"
    OsBuildNumber               = "Unknown"
    OsHardwareAbstractionLayer  = "Unknown"
  }

  try {
    # Try Get-ComputerInfo first (Windows 10+, full installations)
    $ci = Get-ComputerInfo -ErrorAction Stop
    $osInfo.WindowsProductName = $ci.WindowsProductName
    $osInfo.WindowsVersion = $ci.WindowsVersion
    $osInfo.OsBuildNumber = $ci.OsBuildNumber
    $osInfo.OsHardwareAbstractionLayer = $ci.OsHardwareAbstractionLayer
  }
  catch {
    # Fallback to WMI/CIM for older systems or Server Core
    try {
      $wmi = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
      $osInfo.WindowsProductName = $wmi.Caption
      $osInfo.WindowsVersion = $wmi.Version
      $osInfo.OsBuildNumber = $wmi.BuildNumber
    }
    catch {
      Write-Warning "Could not retrieve OS information: $_"
    }
  }

  return $osInfo
}

function Get-RecentHotfixes {
  param([int]$Count = 10)
  
  try {
    $hotfixes = Get-HotFix -ErrorAction Stop | 
      Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | 
      Select-Object -First $Count |
      ForEach-Object { $_.HotFixID }
    return ($hotfixes -join ";")
  }
  catch {
    Write-Warning "Could not retrieve hotfix information: $_"
    return "Unknown"
  }
}

function Get-DirectoriesFromPaths {
  param([string[]]$FilePaths)
  
  $FilePaths | ForEach-Object { 
    Split-Path -Path $_ -Parent 
  } | Select-Object -Unique
}

# ============================================================================
# Main Script
# ============================================================================

# Capture OS context (helps explain hash mismatches due to patch levels)
$os = Get-OSContext
$hotfix = Get-RecentHotfixes -Count 10

Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "Windows Binary Integrity Checker" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "OS: $($os.WindowsProductName) $($os.WindowsVersion) Build $($os.OsBuildNumber)"
Write-Host "Hash Algorithm: $HashAlg"
Write-Host "Recent Hotfixes (top 10): $hotfix"
Write-Host ""

$targets = Resolve-ScanTargets -Paths $Paths -Recurse:$Recurse
Write-Host "Scan targets: $($targets.Count) files"
Write-Host ""

# ============================================================================
# Baseline Mode
# ============================================================================
if ($Mode -eq "Baseline") {
  Write-Host "Mode: BASELINE - Creating known-good hash database" -ForegroundColor Green
  Write-Host ""

  $data = foreach ($t in $targets) { 
    Write-Verbose "Processing: $t"
    Get-FileMeta -Path $t 
  }

  $totalScanned = ($data | Where-Object { $_.Exists }).Count
  $errorCount = ($data | Where-Object { $_.Hash -eq "ERROR" }).Count

  if ($IncludeAll) {
    # Include all files regardless of signature
    $output = $data | Where-Object { $_.Exists -and $_.Hash -ne "ERROR" }
    Write-Host "Including ALL files (not filtered by signature)" -ForegroundColor Yellow
  }
  else {
    # Filter to Microsoft-signed only (recommended for system baseline)
    $msOnly = $data | Where-Object {
      $_.Exists -and 
      $_.Hash -ne "ERROR" -and
      $_.SigStatus -eq "Valid" -and 
      $_.Signer -match "Microsoft"
    }
    
    $nonMs = $data | Where-Object {
      $_.Exists -and 
      $_.Hash -ne "ERROR" -and
      ($_.SigStatus -ne "Valid" -or $_.Signer -notmatch "Microsoft")
    }
    
    if ($nonMs.Count -gt 0) {
      Write-Host "Filtered out $($nonMs.Count) non-Microsoft-signed files:" -ForegroundColor Yellow
      $nonMs | Select-Object -First 10 Path, SigStatus, Signer | Format-Table -AutoSize
      if ($nonMs.Count -gt 10) {
        Write-Host "  ... and $($nonMs.Count - 10) more (use -IncludeAll to include these)" -ForegroundColor Yellow
      }
      Write-Host ""
    }
    
    $output = $msOnly
  }

  $output | Export-Csv -NoTypeInformation -Path $OutFile
  
  Write-Host "=" * 70 -ForegroundColor Cyan
  Write-Host "Baseline Summary" -ForegroundColor Green
  Write-Host "  Output file: $OutFile"
  Write-Host "  Total scanned: $totalScanned"
  Write-Host "  Entries saved: $($output.Count)"
  if ($errorCount -gt 0) {
    Write-Host "  Errors: $errorCount (check warnings above)" -ForegroundColor Yellow
  }
  Write-Host "=" * 70 -ForegroundColor Cyan
  
  exit 0
}

# ============================================================================
# Verify Mode
# ============================================================================
if ($Mode -eq "Verify") {
  Write-Host "Mode: VERIFY - Checking against baseline" -ForegroundColor Green
  Write-Host ""

  if (-not $BaselineFile) { 
    throw "Verify mode requires -BaselineFile parameter" 
  }
  if (-not (Test-Path -LiteralPath $BaselineFile)) { 
    throw "BaselineFile not found: $BaselineFile" 
  }

  $baseline = Import-Csv -Path $BaselineFile
  
  # Validate hash algorithm matches
  $baselineAlg = $baseline | Select-Object -First 1 -ExpandProperty HashAlg -ErrorAction SilentlyContinue
  if ($baselineAlg -and $baselineAlg -ne $HashAlg) {
    Write-Warning "Hash algorithm mismatch! Baseline uses '$baselineAlg', but current setting is '$HashAlg'"
    Write-Warning "Switching to baseline algorithm: $baselineAlg"
    $script:HashAlgorithm = $baselineAlg
    $HashAlg = $baselineAlg
  }

  Write-Host "Baseline entries: $($baseline.Count)"
  Write-Host ""

  $baseIndex = @{}
  foreach ($b in $baseline) { 
    $baseIndex[$b.Path] = $b 
  }

  # Verify baseline entries
  $results = [System.Collections.ArrayList]::new()
  
  foreach ($b in $baseline) {
    Write-Verbose "Verifying: $($b.Path)"
    $cur = Get-FileMeta -Path $b.Path

    $status = if (-not $cur.Exists) { 
      "MISSING" 
    }
    elseif ($cur.Hash -eq "ERROR") {
      "ERROR"
    }
    elseif ($cur.Hash -ne $b.Hash) { 
      "HASH_MISMATCH" 
    }
    elseif ($cur.SigStatus -ne "Valid") {
      "SIGNATURE_INVALID"
    }
    elseif ($cur.Signer -notmatch "Microsoft") { 
      "SIGNATURE_SUSPICIOUS" 
    }
    else { 
      "OK" 
    }

    $null = $results.Add([pscustomobject]@{
      Status              = $status
      Path                = $cur.Path
      Exists              = $cur.Exists
      HashAlg             = $HashAlg
      BaselineHash        = $b.Hash
      CurrentHash         = $cur.Hash
      HashMatch           = ($cur.Hash -eq $b.Hash)
      BaselineFileVersion = $b.FileVersion
      CurrentFileVersion  = $cur.FileVersion
      VersionMatch        = ($cur.FileVersion -eq $b.FileVersion)
      SigStatus           = $cur.SigStatus
      Signer              = $cur.Signer
      Company             = $cur.Company
      Product             = $cur.Product
      Length              = $cur.Length
      LastWriteTimeUtc    = $cur.LastWriteTime
      OS_Build            = $os.OsBuildNumber
      RecentHotfixes      = $hotfix
    })
  }

  # Detect new/unexpected files if requested
  if ($DetectNewFiles) {
    Write-Host "Scanning for new/unexpected files..." -ForegroundColor Yellow
    
    # Get directories from baseline
    $baselineDirs = Get-DirectoriesFromPaths -FilePaths ($baseline | ForEach-Object { $_.Path })
    
    # Scan those directories for current files
    $currentFiles = Resolve-ScanTargets -Paths $baselineDirs -Recurse:$Recurse
    
    # Find files not in baseline
    $newFiles = $currentFiles | Where-Object { -not $baseIndex.ContainsKey($_) }
    
    foreach ($newFile in $newFiles) {
      Write-Verbose "New file detected: $newFile"
      $cur = Get-FileMeta -Path $newFile
      
      # Determine if this new file is suspicious
      $status = if ($cur.SigStatus -ne "Valid") {
        "NEW_UNSIGNED"
      }
      elseif ($cur.Signer -notmatch "Microsoft") {
        "NEW_THIRD_PARTY"
      }
      else {
        "NEW_MS_SIGNED"
      }

      $null = $results.Add([pscustomobject]@{
        Status              = $status
        Path                = $cur.Path
        Exists              = $cur.Exists
        HashAlg             = $HashAlg
        BaselineHash        = "[NOT IN BASELINE]"
        CurrentHash         = $cur.Hash
        HashMatch           = $false
        BaselineFileVersion = "[NOT IN BASELINE]"
        CurrentFileVersion  = $cur.FileVersion
        VersionMatch        = $false
        SigStatus           = $cur.SigStatus
        Signer              = $cur.Signer
        Company             = $cur.Company
        Product             = $cur.Product
        Length              = $cur.Length
        LastWriteTimeUtc    = $cur.LastWriteTime
        OS_Build            = $os.OsBuildNumber
        RecentHotfixes      = $hotfix
      })
    }
    
    Write-Host "New files detected: $($newFiles.Count)" -ForegroundColor $(if ($newFiles.Count -gt 0) { "Yellow" } else { "Green" })
  }

  $results | Export-Csv -NoTypeInformation -Path $OutFile

  # Console summary
  Write-Host ""
  Write-Host "=" * 70 -ForegroundColor Cyan
  Write-Host "Verification Summary" -ForegroundColor Green
  Write-Host "  Report file: $OutFile"
  Write-Host ""
  
  $summary = $results | Group-Object Status | Sort-Object Name
  foreach ($s in $summary) {
    $color = switch ($s.Name) {
      "OK"           { "Green" }
      "NEW_MS_SIGNED" { "Yellow" }
      default        { "Red" }
    }
    Write-Host ("  {0,-22} {1,6}" -f $s.Name, $s.Count) -ForegroundColor $color
  }
  
  Write-Host ""
  Write-Host "=" * 70 -ForegroundColor Cyan

  # Show suspicious entries
  $suspicious = $results | Where-Object { $_.Status -ne "OK" -and $_.Status -ne "NEW_MS_SIGNED" }
  
  if ($suspicious.Count -gt 0) {
    Write-Host ""
    Write-Host "SUSPICIOUS ENTRIES (requires investigation):" -ForegroundColor Red
    Write-Host "-" * 70 -ForegroundColor Red
    
    $suspicious | 
      Select-Object -First 20 Status, Path, SigStatus, Signer, BaselineHash, CurrentHash | 
      Format-Table -AutoSize -Wrap
    
    if ($suspicious.Count -gt 20) {
      Write-Host "... and $($suspicious.Count - 20) more suspicious entries. See full report." -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "RECOMMENDATION: Investigate all non-OK entries, especially HASH_MISMATCH" -ForegroundColor Yellow
    Write-Host "Hash mismatches may indicate tampering OR Windows updates. Check patch levels." -ForegroundColor Yellow
  }
  else {
    Write-Host ""
    Write-Host "All baseline files verified OK!" -ForegroundColor Green
  }
}
