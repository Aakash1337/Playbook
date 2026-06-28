<#
.SYNOPSIS
  Comprehensive Windows system inventory (read-only) for blue-team baselining and triage.

.DESCRIPTION
  Collects OS/hardware/storage/network/security/software/services/processes/scheduled tasks/
  firewall/open ports/shares/certificates/patches/policies/persistence/autoruns and exports:
    - inventory.json (summary + file references)
    - multiple CSVs for list-style data (software/services/processes/tasks/firewall/etc.)
    - system_report.html (enhanced readable summary)
    - text artifacts (route/arp/netstat/systeminfo)
    - collection.log (execution log with errors)

  Designed to run on PowerShell 5.1+ without external modules.
  Degrades gracefully if certain cmdlets are missing.

.PARAMETER OutputRoot
  Base directory for report output (default: current directory).

.PARAMETER Quick
  Skip expensive/verbose collections (e.g., AppX packages, full firewall rule export, cert enumeration).

.PARAMETER IncludeEventLogs
  Include a small event log summary (last 24 hours) from System and Security. Can be slower.

.PARAMETER Software
  Include installed software inventory (registry + AppX if available). Disable with -Software:$false.

.PARAMETER Firewall
  Include firewall rules export. Disable with -Firewall:$false.

.PARAMETER Certs
  Include LocalMachine certificate inventory. Disable with -Certs:$false.

.PARAMETER Compress
  Compress the output folder into a ZIP archive after collection.

.PARAMETER NoProgress
  Disable progress indicators (useful for scripted/automated runs).

.PARAMETER UpdateBaseline
  Force update/create baseline with current inventory. Use after system hardening or to refresh baseline.

.PARAMETER BaselinePath
  Custom baseline directory location (default: .\baseline in script directory).

.PARAMETER SkipComparison
  Skip baseline comparison even if baseline exists. Use for quick inventory without diff.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Get-WindowsInventory.ps1

.EXAMPLE
  .\Get-WindowsInventory.ps1 -OutputRoot C:\IR -IncludeEventLogs -Quick -Compress

.EXAMPLE
  .\Get-WindowsInventory.ps1 -UpdateBaseline

.EXAMPLE
  .\Get-WindowsInventory.ps1 -BaselinePath "D:\SecureBaseline"

.NOTES
  Run as Administrator for best coverage (SecurityCenter2, some registry keys, firewall rules, etc.).
  CCDC READY: Includes threat detection, suspicious activity flagging, and security baseline checks.
  Version: 2.1 (CCDC Enhanced)
#>

[CmdletBinding()]
param(
  [string]$OutputRoot = (Get-Location).Path,
  [switch]$Quick,
  [switch]$IncludeEventLogs,
  [bool]$Software = $true,
  [bool]$Firewall = $true,
  [bool]$Certs = $true,
  [switch]$Compress,
  [switch]$NoProgress,
  [switch]$UpdateBaseline,
  [string]$BaselinePath = "",
  [switch]$SkipComparison
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Script-level variables
$script:LogPath = $null
$script:ErrorLog = @()
$script:StartTime = Get-Date
$script:TotalSteps = 25
$script:CurrentStep = 0

# ---------------------------- Helpers ----------------------------

function Write-ProgressSafe {
  param(
    [Parameter(Mandatory)][string]$Activity,
    [Parameter(Mandatory)][string]$Status,
    [int]$PercentComplete = 0
  )
  
  if (-not $NoProgress) {
    try {
      Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    } catch {}
  }
}

function Update-Progress {
  param([string]$Status)
  
  $script:CurrentStep++
  $percent = [math]::Min(100, [int](($script:CurrentStep / $script:TotalSteps) * 100))
  Write-ProgressSafe -Activity "Windows Inventory Collection" -Status $Status -PercentComplete $percent
}

function Write-LogEntry {
  param(
    [Parameter(Mandatory)][string]$Message,
    [string]$Level = "INFO"
  )
  
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $logEntry = "[$timestamp] [$Level] $Message"
  
  # Console output
  switch ($Level) {
    "ERROR" { Write-Host $logEntry -ForegroundColor Red }
    "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
    "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
    default { Write-Host $logEntry }
  }
  
  # File output
  if ($script:LogPath) {
    try {
      $logEntry | Out-File -Append -FilePath $script:LogPath -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
  }
}

function Add-ErrorEntry {
  param(
    [Parameter(Mandatory)][string]$Function,
    [Parameter(Mandatory)][string]$Error
  )
  
  $script:ErrorLog += [pscustomobject]@{
    Timestamp = Get-Date
    Function = $Function
    Error = $Error
  }
  
  Write-LogEntry -Message "Error in $Function : $Error" -Level "ERROR"
}

function Test-Command {
  param([Parameter(Mandatory)][string]$Name)
  return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function New-ReportFolder {
  param([string]$Root)

  $ts = Get-Date -Format "yyyyMMdd_HHmmss"
  $hostName = $env:COMPUTERNAME
  $dir = Join-Path $Root "Inventory_${hostName}_$ts"

  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $dir "artifacts") -Force | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $dir "csv") -Force | Out-Null
  
  # Initialize log file
  $script:LogPath = Join-Path $dir "collection.log"
  
  return $dir
}

function Write-TextFile {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Content
  )
  $Content | Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Export-CsvSafe {
  param(
    [Parameter(Mandatory)]$Data,
    [Parameter(Mandatory)][string]$Path
  )
  if ($null -eq $Data -or @($Data).Count -eq 0) {
    "" | Out-File -FilePath $Path -Encoding UTF8 -Force
    return
  }
  $Data | Export-Csv -NoTypeInformation -Encoding UTF8 -Force -Path $Path
}

function Get-FileHashSafe {
  param([string]$Path)
  try {
    if (Test-Path $Path) {
      if (Test-Command "Get-FileHash") {
        return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash
      } else {
        # Fallback: certutil
        $out = certutil -hashfile $Path SHA256 2>$null
        return ($out | Select-String -Pattern '^[0-9A-Fa-f]{64}$').Line
      }
    }
  } catch {}
  return $null
}

function Get-RegistryValueSafe {
  param([string]$Path, [string]$Name)
  try {
    $item = Get-ItemProperty -Path $Path -ErrorAction Stop
    return $item.$Name
  } catch {
    return $null
  }
}

function Invoke-ExeCapture {
  param(
    [Parameter(Mandatory)][string]$File,
    [string[]]$Args = @()
  )
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $File
    $psi.Arguments = ($Args -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    return [pscustomobject]@{
      ExitCode = $p.ExitCode
      StdOut   = $stdout
      StdErr   = $stderr
    }
  } catch {
    return [pscustomobject]@{ 
      ExitCode = 1
      StdOut = ""
      StdErr = $_.Exception.Message 
    }
  }
}

function Is-Admin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { 
    return $false 
  }
}

function Compress-ReportFolder {
  param([string]$FolderPath)
  
  try {
    $zipPath = "$FolderPath.zip"
    
    if (Test-Command "Compress-Archive") {
      Write-LogEntry "Compressing report folder..."
      Compress-Archive -Path $FolderPath -DestinationPath $zipPath -CompressionLevel Optimal -Force
      Write-LogEntry "Compressed report: $zipPath" -Level "SUCCESS"
      return $zipPath
    } else {
      Write-LogEntry "Compress-Archive not available, skipping compression" -Level "WARN"
    }
  } catch {
    Write-LogEntry "Failed to compress: $_" -Level "ERROR"
    Add-ErrorEntry -Function "Compress-ReportFolder" -Error $_.Exception.Message
  }
  
  return $null
}

# ---------------------------- Baseline Management Functions ----------------------------

function Get-BaselineDirectory {
  param([string]$CustomPath)

  if ($CustomPath) {
    return $CustomPath
  }

  $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
  if (-not $scriptDir) {
    $scriptDir = Get-Location
  }

  return Join-Path $scriptDir "baseline"
}

function Test-BaselineExists {
  param([string]$BaselineDir)

  $metadataPath = Join-Path $BaselineDir "baseline_metadata.json"
  return (Test-Path $metadataPath)
}

function Save-Baseline {
  param(
    [Parameter(Mandatory)][string]$BaselineDir,
    [Parameter(Mandatory)][hashtable]$Inventory
  )

  try {
    # Create baseline directory if it doesn't exist
    if (-not (Test-Path $BaselineDir)) {
      New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null
    }

    Write-LogEntry "Saving baseline to $BaselineDir"

    # Save metadata
    $metadata = @{
      CreatedAt = (Get-Date).ToString("o")
      ComputerName = $env:COMPUTERNAME
      Version = "2.1-CCDC"
    }
    $metadataPath = Join-Path $BaselineDir "baseline_metadata.json"
    ($metadata | ConvertTo-Json) | Out-File -FilePath $metadataPath -Encoding UTF8 -Force

    # Copy CSV files to baseline
    $csvMappings = @{
      "baseline_processes.csv" = $Inventory.Processes.Csv
      "baseline_services.csv" = $Inventory.Services.Csv
      "baseline_tasks.csv" = $Inventory.Tasks.Csv
      "baseline_users.csv" = $Inventory.Users.UsersCsv
      "baseline_group_members.csv" = $Inventory.Users.MembersCsv
      "baseline_software.csv" = $Inventory.Software.UninstallCsv
      "baseline_autoruns.csv" = $Inventory.Autoruns.Csv
      "baseline_connections.csv" = $Inventory.EstablishedConnections.Csv
      "baseline_patches.csv" = $Inventory.Patches.Csv
      "baseline_shares.csv" = $Inventory.Shares.Csv
    }

    foreach ($baseline in $csvMappings.Keys) {
      $sourcePath = $csvMappings[$baseline]
      if ($sourcePath -and (Test-Path $sourcePath)) {
        $destPath = Join-Path $BaselineDir $baseline
        Copy-Item -Path $sourcePath -Destination $destPath -Force
      }
    }

    Write-LogEntry "Baseline saved successfully" -Level "SUCCESS"
    return $true
  } catch {
    Write-LogEntry "Failed to save baseline: $_" -Level "ERROR"
    Add-ErrorEntry -Function "Save-Baseline" -Error $_.Exception.Message
    return $false
  }
}

function Compare-WithBaseline {
  param(
    [Parameter(Mandatory)][string]$BaselineDir,
    [Parameter(Mandatory)][hashtable]$CurrentInventory,
    [Parameter(Mandatory)][string]$ComparisonCsvDir
  )

  $comparison = @{
    Processes = @{ Added = @(); Removed = @(); Count = 0; Csv = $null }
    Services = @{ Added = @(); Removed = @(); Count = 0; Csv = $null }
    Tasks = @{ Added = @(); Removed = @(); Count = 0; Csv = $null }
    Users = @{ Added = @(); Removed = @(); Count = 0; Csv = $null }
    Admins = @{ Added = @(); Removed = @(); Count = 0; Csv = $null }
    Software = @{ Added = @(); Removed = @(); Count = 0; Csv = $null }
    Autoruns = @{ Added = @(); Removed = @(); Count = 0; Csv = $null }
    Shares = @{ Added = @(); Removed = @(); Count = 0; Csv = $null }
    TotalChanges = 0
  }

  try {
    # Load baseline metadata
    $metadataPath = Join-Path $BaselineDir "baseline_metadata.json"
    $metadata = Get-Content $metadataPath -Raw | ConvertFrom-Json
    $comparison.BaselineDate = $metadata.CreatedAt

    # Compare Processes
    $baselineProc = Join-Path $BaselineDir "baseline_processes.csv"
    if ((Test-Path $baselineProc) -and $CurrentInventory.Processes.Csv -and (Test-Path $CurrentInventory.Processes.Csv)) {
      $baseData = Import-Csv $baselineProc
      $currData = Import-Csv $CurrentInventory.Processes.Csv

      $baseNames = $baseData | Select-Object -ExpandProperty Name -Unique
      $currNames = $currData | Select-Object -ExpandProperty Name -Unique

      $addedNames = @($currNames | Where-Object { $_ -notin $baseNames })
      $removedNames = @($baseNames | Where-Object { $_ -notin $currNames })

      $comparison.Processes.Added = $addedNames
      $comparison.Processes.Removed = $removedNames
      $comparison.Processes.Count = $addedNames.Count + $removedNames.Count

      # Save comparison CSV
      if ($comparison.Processes.Count -gt 0) {
        $comparisonData = @()
        foreach ($name in $addedNames) {
          $proc = $currData | Where-Object { $_.Name -eq $name } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "ADDED"
            Name = $name
            Id = $proc.Id
            Path = $proc.Path
            CommandLine = $proc.CommandLine
          }
        }
        foreach ($name in $removedNames) {
          $proc = $baseData | Where-Object { $_.Name -eq $name } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "REMOVED"
            Name = $name
            Id = $proc.Id
            Path = $proc.Path
            CommandLine = $proc.CommandLine
          }
        }
        $compCsv = Join-Path $ComparisonCsvDir "comparison_processes.csv"
        Export-CsvSafe -Data $comparisonData -Path $compCsv
        $comparison.Processes.Csv = $compCsv
      }
    }

    # Compare Services
    $baselineSvc = Join-Path $BaselineDir "baseline_services.csv"
    if ((Test-Path $baselineSvc) -and $CurrentInventory.Services.Csv -and (Test-Path $CurrentInventory.Services.Csv)) {
      $baseData = Import-Csv $baselineSvc
      $currData = Import-Csv $CurrentInventory.Services.Csv

      $baseNames = $baseData | Select-Object -ExpandProperty Name -Unique
      $currNames = $currData | Select-Object -ExpandProperty Name -Unique

      $addedNames = @($currNames | Where-Object { $_ -notin $baseNames })
      $removedNames = @($baseNames | Where-Object { $_ -notin $currNames })

      $comparison.Services.Added = $addedNames
      $comparison.Services.Removed = $removedNames
      $comparison.Services.Count = $addedNames.Count + $removedNames.Count

      # Save comparison CSV
      if ($comparison.Services.Count -gt 0) {
        $comparisonData = @()
        foreach ($name in $addedNames) {
          $svc = $currData | Where-Object { $_.Name -eq $name } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "ADDED"
            Name = $name
            DisplayName = $svc.DisplayName
            State = $svc.State
            StartMode = $svc.StartMode
            PathName = $svc.PathName
          }
        }
        foreach ($name in $removedNames) {
          $svc = $baseData | Where-Object { $_.Name -eq $name } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "REMOVED"
            Name = $name
            DisplayName = $svc.DisplayName
            State = $svc.State
            StartMode = $svc.StartMode
            PathName = $svc.PathName
          }
        }
        $compCsv = Join-Path $ComparisonCsvDir "comparison_services.csv"
        Export-CsvSafe -Data $comparisonData -Path $compCsv
        $comparison.Services.Csv = $compCsv
      }
    }

    # Compare Scheduled Tasks
    $baselineTask = Join-Path $BaselineDir "baseline_tasks.csv"
    if ((Test-Path $baselineTask) -and $CurrentInventory.Tasks.Csv -and (Test-Path $CurrentInventory.Tasks.Csv)) {
      $baseData = Import-Csv $baselineTask
      $currData = Import-Csv $CurrentInventory.Tasks.Csv

      $baseNames = $baseData | Select-Object -ExpandProperty TaskName -Unique
      $currNames = $currData | Select-Object -ExpandProperty TaskName -Unique

      $addedNames = @($currNames | Where-Object { $_ -notin $baseNames })
      $removedNames = @($baseNames | Where-Object { $_ -notin $currNames })

      $comparison.Tasks.Added = $addedNames
      $comparison.Tasks.Removed = $removedNames
      $comparison.Tasks.Count = $addedNames.Count + $removedNames.Count

      # Save comparison CSV
      if ($comparison.Tasks.Count -gt 0) {
        $comparisonData = @()
        foreach ($name in $addedNames) {
          $task = $currData | Where-Object { $_.TaskName -eq $name } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "ADDED"
            TaskName = $name
            TaskPath = $task.TaskPath
            State = $task.State
            Author = $task.Author
            Actions = $task.Actions
          }
        }
        foreach ($name in $removedNames) {
          $task = $baseData | Where-Object { $_.TaskName -eq $name } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "REMOVED"
            TaskName = $name
            TaskPath = $task.TaskPath
            State = $task.State
            Author = $task.Author
            Actions = $task.Actions
          }
        }
        $compCsv = Join-Path $ComparisonCsvDir "comparison_tasks.csv"
        Export-CsvSafe -Data $comparisonData -Path $compCsv
        $comparison.Tasks.Csv = $compCsv
      }
    }

    # Compare Users
    $baselineUsers = Join-Path $BaselineDir "baseline_users.csv"
    if ((Test-Path $baselineUsers) -and $CurrentInventory.Users.UsersCsv -and (Test-Path $CurrentInventory.Users.UsersCsv)) {
      $baseData = Import-Csv $baselineUsers
      $currData = Import-Csv $CurrentInventory.Users.UsersCsv

      $baseNames = $baseData | Select-Object -ExpandProperty Name -Unique
      $currNames = $currData | Select-Object -ExpandProperty Name -Unique

      $addedNames = @($currNames | Where-Object { $_ -notin $baseNames })
      $removedNames = @($baseNames | Where-Object { $_ -notin $currNames })

      $comparison.Users.Added = $addedNames
      $comparison.Users.Removed = $removedNames
      $comparison.Users.Count = $addedNames.Count + $removedNames.Count

      # Save comparison CSV
      if ($comparison.Users.Count -gt 0) {
        $comparisonData = @()
        foreach ($name in $addedNames) {
          $user = $currData | Where-Object { $_.Name -eq $name } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "ADDED"
            Name = $name
            Enabled = $user.Enabled
            LastLogon = $user.LastLogon
            Description = $user.Description
          }
        }
        foreach ($name in $removedNames) {
          $user = $baseData | Where-Object { $_.Name -eq $name } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "REMOVED"
            Name = $name
            Enabled = $user.Enabled
            LastLogon = $user.LastLogon
            Description = $user.Description
          }
        }
        $compCsv = Join-Path $ComparisonCsvDir "comparison_users.csv"
        Export-CsvSafe -Data $comparisonData -Path $compCsv
        $comparison.Users.Csv = $compCsv
      }
    }

    # Compare Administrators
    $baselineAdmins = Join-Path $BaselineDir "baseline_group_members.csv"
    if ((Test-Path $baselineAdmins) -and $CurrentInventory.Users.MembersCsv -and (Test-Path $CurrentInventory.Users.MembersCsv)) {
      $baseData = Import-Csv $baselineAdmins | Where-Object { $_.Group -match 'Administrators' }
      $currData = Import-Csv $CurrentInventory.Users.MembersCsv | Where-Object { $_.Group -match 'Administrators' }

      $baseMembers = $baseData | Select-Object -ExpandProperty Member -Unique
      $currMembers = $currData | Select-Object -ExpandProperty Member -Unique

      $addedMembers = @($currMembers | Where-Object { $_ -notin $baseMembers })
      $removedMembers = @($baseMembers | Where-Object { $_ -notin $currMembers })

      $comparison.Admins.Added = $addedMembers
      $comparison.Admins.Removed = $removedMembers
      $comparison.Admins.Count = $addedMembers.Count + $removedMembers.Count

      # Save comparison CSV
      if ($comparison.Admins.Count -gt 0) {
        $comparisonData = @()
        foreach ($member in $addedMembers) {
          $admin = $currData | Where-Object { $_.Member -eq $member } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "ADDED"
            Member = $member
            Group = $admin.Group
            ObjectClass = $admin.ObjectClass
            PrincipalSource = $admin.PrincipalSource
          }
        }
        foreach ($member in $removedMembers) {
          $admin = $baseData | Where-Object { $_.Member -eq $member } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "REMOVED"
            Member = $member
            Group = $admin.Group
            ObjectClass = $admin.ObjectClass
            PrincipalSource = $admin.PrincipalSource
          }
        }
        $compCsv = Join-Path $ComparisonCsvDir "comparison_administrators.csv"
        Export-CsvSafe -Data $comparisonData -Path $compCsv
        $comparison.Admins.Csv = $compCsv
      }
    }

    # Compare Software
    $baselineSoft = Join-Path $BaselineDir "baseline_software.csv"
    if ((Test-Path $baselineSoft) -and $CurrentInventory.Software.UninstallCsv -and (Test-Path $CurrentInventory.Software.UninstallCsv)) {
      $baseData = Import-Csv $baselineSoft
      $currData = Import-Csv $CurrentInventory.Software.UninstallCsv

      $baseNames = $baseData | Select-Object -ExpandProperty DisplayName -Unique
      $currNames = $currData | Select-Object -ExpandProperty DisplayName -Unique

      $addedNames = @($currNames | Where-Object { $_ -notin $baseNames })
      $removedNames = @($baseNames | Where-Object { $_ -notin $currNames })

      $comparison.Software.Added = $addedNames
      $comparison.Software.Removed = $removedNames
      $comparison.Software.Count = $addedNames.Count + $removedNames.Count

      # Save comparison CSV
      if ($comparison.Software.Count -gt 0) {
        $comparisonData = @()
        foreach ($name in $addedNames) {
          $sw = $currData | Where-Object { $_.DisplayName -eq $name } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "ADDED"
            DisplayName = $name
            DisplayVersion = $sw.DisplayVersion
            Publisher = $sw.Publisher
            InstallDate = $sw.InstallDate
          }
        }
        foreach ($name in $removedNames) {
          $sw = $baseData | Where-Object { $_.DisplayName -eq $name } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "REMOVED"
            DisplayName = $name
            DisplayVersion = $sw.DisplayVersion
            Publisher = $sw.Publisher
            InstallDate = $sw.InstallDate
          }
        }
        $compCsv = Join-Path $ComparisonCsvDir "comparison_software.csv"
        Export-CsvSafe -Data $comparisonData -Path $compCsv
        $comparison.Software.Csv = $compCsv
      }
    }

    # Compare Autoruns
    $baselineAuto = Join-Path $BaselineDir "baseline_autoruns.csv"
    if ((Test-Path $baselineAuto) -and $CurrentInventory.Autoruns.Csv -and (Test-Path $CurrentInventory.Autoruns.Csv)) {
      $baseData = Import-Csv $baselineAuto
      $currData = Import-Csv $CurrentInventory.Autoruns.Csv

      $baseItems = $baseData | ForEach-Object { "$($_.Location)|$($_.Name)" }
      $currItems = $currData | ForEach-Object { "$($_.Location)|$($_.Name)" }

      $addedItems = @($currItems | Where-Object { $_ -notin $baseItems })
      $removedItems = @($baseItems | Where-Object { $_ -notin $currItems })

      $comparison.Autoruns.Added = @($addedItems | ForEach-Object { $_.Split('|')[1] })
      $comparison.Autoruns.Removed = @($removedItems | ForEach-Object { $_.Split('|')[1] })
      $comparison.Autoruns.Count = $addedItems.Count + $removedItems.Count

      # Save comparison CSV
      if ($comparison.Autoruns.Count -gt 0) {
        $comparisonData = @()
        foreach ($item in $addedItems) {
          $parts = $item.Split('|')
          $autorun = $currData | Where-Object { $_.Location -eq $parts[0] -and $_.Name -eq $parts[1] } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "ADDED"
            Name = $parts[1]
            Location = $parts[0]
            Type = $autorun.Type
            Value = $autorun.Value
          }
        }
        foreach ($item in $removedItems) {
          $parts = $item.Split('|')
          $autorun = $baseData | Where-Object { $_.Location -eq $parts[0] -and $_.Name -eq $parts[1] } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "REMOVED"
            Name = $parts[1]
            Location = $parts[0]
            Type = $autorun.Type
            Value = $autorun.Value
          }
        }
        $compCsv = Join-Path $ComparisonCsvDir "comparison_autoruns.csv"
        Export-CsvSafe -Data $comparisonData -Path $compCsv
        $comparison.Autoruns.Csv = $compCsv
      }
    }

    # Compare Shares
    $baselineShares = Join-Path $BaselineDir "baseline_shares.csv"
    if ((Test-Path $baselineShares) -and $CurrentInventory.Shares.Csv -and (Test-Path $CurrentInventory.Shares.Csv)) {
      $baseData = Import-Csv $baselineShares
      $currData = Import-Csv $CurrentInventory.Shares.Csv

      $baseNames = $baseData | Select-Object -ExpandProperty Name -Unique
      $currNames = $currData | Select-Object -ExpandProperty Name -Unique

      $addedNames = @($currNames | Where-Object { $_ -notin $baseNames })
      $removedNames = @($baseNames | Where-Object { $_ -notin $currNames })

      $comparison.Shares.Added = $addedNames
      $comparison.Shares.Removed = $removedNames
      $comparison.Shares.Count = $addedNames.Count + $removedNames.Count

      # Save comparison CSV
      if ($comparison.Shares.Count -gt 0) {
        $comparisonData = @()
        foreach ($name in $addedNames) {
          $share = $currData | Where-Object { $_.Name -eq $name } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "ADDED"
            Name = $name
            Path = $share.Path
            Description = $share.Description
          }
        }
        foreach ($name in $removedNames) {
          $share = $baseData | Where-Object { $_.Name -eq $name } | Select-Object -First 1
          $comparisonData += [pscustomobject]@{
            Change = "REMOVED"
            Name = $name
            Path = $share.Path
            Description = $share.Description
          }
        }
        $compCsv = Join-Path $ComparisonCsvDir "comparison_shares.csv"
        Export-CsvSafe -Data $comparisonData -Path $compCsv
        $comparison.Shares.Csv = $compCsv
      }
    }

    # Calculate total changes
    $comparison.TotalChanges = $comparison.Processes.Count + $comparison.Services.Count +
                               $comparison.Tasks.Count + $comparison.Users.Count +
                               $comparison.Admins.Count + $comparison.Software.Count +
                               $comparison.Autoruns.Count + $comparison.Shares.Count

    Write-LogEntry "Baseline comparison complete: $($comparison.TotalChanges) total changes detected"

    return $comparison
  } catch {
    Write-LogEntry "Failed to compare with baseline: $_" -Level "ERROR"
    Add-ErrorEntry -Function "Compare-WithBaseline" -Error $_.Exception.Message
    return $null
  }
}

# ---------------------------- CCDC Threat Detection Functions ----------------------------

function Test-SuspiciousProcess {
  param([object]$Process)

  $suspicious = @()

  # Get path from either Path or ExecutablePath property, handling null
  $path = $null
  if ($Process.PSObject.Properties['Path'] -and $Process.Path) {
    $path = $Process.Path
  } elseif ($Process.PSObject.Properties['ExecutablePath'] -and $Process.ExecutablePath) {
    $path = $Process.ExecutablePath
  }

  # Only check paths if we have one
  if ($path) {
    # Check for suspicious paths
    if ($path -match '(temp|appdata\\local\\temp|public|programdata|users\\public|windows\\temp)') {
      $suspicious += "Running from suspicious location: $path"
    }

    # Check for double extensions
    if ($path -match '\.(pdf|doc|xls|jpg|png|txt)\.(exe|scr|pif|bat|cmd|vbs|js)$') {
      $suspicious += "Double extension detected: $path"
    }
  }

  # Check for suspicious names (always available)
  if ($Process.Name -match '^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)$') {
    $suspicious += "Suspicious process name: $($Process.Name)"
  }

  return ,$suspicious
}

function Test-SuspiciousService {
  param([object]$Service)

  $suspicious = @()
  $path = $Service.PathName

  # Check for suspicious paths
  if ($path -match '(temp|appdata|public|programdata|users)' -and $Service.StartMode -eq 'Auto') {
    $suspicious += "Auto-start service in user directory: $path"
  }

  # Check for services running as SYSTEM from suspicious locations
  if ($Service.StartName -eq 'LocalSystem' -and $path -match '(users|temp)') {
    $suspicious += "SYSTEM service in user directory: $path"
  }

  # Check for encoded commands
  if ($path -match '-enc|-encodedcommand') {
    $suspicious += "Service using encoded commands: $path"
  }

  return ,$suspicious
}

function Test-SuspiciousScheduledTask {
  param([object]$Task)

  $suspicious = @()
  $actions = $Task.Actions

  # Check for suspicious actions
  if ($actions -match '(temp|appdata\\local\\temp|public|programdata\\public)') {
    $suspicious += "Task runs from suspicious location: $actions"
  }

  # Check for PowerShell with encoded commands
  if ($actions -match 'powershell.*(-enc|-encodedcommand|-w hidden|-windowstyle hidden)') {
    $suspicious += "Task uses hidden/encoded PowerShell: $actions"
  }

  # Check for tasks running as SYSTEM
  if ($Task.TaskPath -match '\\Microsoft\\Windows\\' -and $Task.Author -notmatch 'Microsoft') {
    $suspicious += "Non-Microsoft task in Microsoft folder: $($Task.TaskPath)"
  }

  return ,$suspicious
}

function Test-UnauthorizedAdmin {
  param([object]$GroupMember)

  # Common legitimate admin accounts (customize for your environment)
  $legitimateAdmins = @(
    'Administrator',
    'Domain Admins',
    'Enterprise Admins'
  )

  if ($GroupMember.Group -match 'Administrators' -and
      $GroupMember.Member -notmatch ($legitimateAdmins -join '|')) {
    return $true
  }

  return $false
}

function Get-RecentFileModifications {
  param([int]$Hours = 24)

  $since = (Get-Date).AddHours(-$Hours)
  $suspiciousPaths = @(
    "$env:SystemRoot\System32\drivers\etc",
    "$env:SystemRoot\System32\drivers",
    "$env:SystemRoot\System32",
    "$env:SystemRoot\SysWOW64"
  )

  $modifications = @()
  foreach ($path in $suspiciousPaths) {
    if (Test-Path $path) {
      try {
        $files = Get-ChildItem $path -File -ErrorAction SilentlyContinue |
          Where-Object { $_.LastWriteTime -gt $since }

        foreach ($file in $files) {
          $modifications += [pscustomobject]@{
            Path = $file.FullName
            LastWriteTime = $file.LastWriteTime
            Size = $file.Length
            Hash = (Get-FileHashSafe $file.FullName)
          }
        }
      } catch {}
    }
  }

  return ,$modifications
}

function Get-SuspiciousNetworkConnections {
  param([object[]]$Connections)

  $suspicious = @()

  foreach ($conn in $Connections) {
    # Check for connections to common C2 ports
    if ($conn.RemotePort -in @(4444, 5555, 6666, 7777, 8888, 31337, 1337)) {
      $suspicious += [pscustomobject]@{
        LocalAddress = $conn.LocalAddress
        LocalPort = $conn.LocalPort
        RemoteAddress = $conn.RemoteAddress
        RemotePort = $conn.RemotePort
        ProcessId = $conn.ProcessId
        ProcessName = $conn.ProcessName
        Reason = "Common C2 port: $($conn.RemotePort)"
      }
    }

    # Check for non-standard ports on common processes
    if ($conn.ProcessName -match '^(notepad|calc|mspaint)$' -and $conn.RemotePort -ne 0) {
      $suspicious += [pscustomobject]@{
        LocalAddress = $conn.LocalAddress
        LocalPort = $conn.LocalPort
        RemoteAddress = $conn.RemoteAddress
        RemotePort = $conn.RemotePort
        ProcessId = $conn.ProcessId
        ProcessName = $conn.ProcessName
        Reason = "Unusual process with network connection: $($conn.ProcessName)"
      }
    }
  }

  return ,$suspicious
}

function Get-SecurityWeaknesses {
  $weaknesses = @()

  # Check UAC
  $uacEnabled = Get-RegistryValueSafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
  if ($uacEnabled -ne 1) {
    $weaknesses += [pscustomobject]@{
      Category = "UAC"
      Issue = "User Account Control is disabled"
      Risk = "High"
      Recommendation = "Enable UAC"
    }
  }

  # Check RDP
  $rdpDeny = Get-RegistryValueSafe "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
  if ($rdpDeny -eq 0) {
    $weaknesses += [pscustomobject]@{
      Category = "RDP"
      Issue = "Remote Desktop is enabled"
      Risk = "Medium"
      Recommendation = "Disable RDP if not needed, or restrict access"
    }
  }

  # Check Windows Firewall
  if (Test-Command "Get-NetFirewallProfile") {
    try {
      $profiles = Get-NetFirewallProfile -ErrorAction Stop
      foreach ($profile in $profiles) {
        if (-not $profile.Enabled) {
          $weaknesses += [pscustomobject]@{
            Category = "Firewall"
            Issue = "Windows Firewall is disabled for $($profile.Name) profile"
            Risk = "High"
            Recommendation = "Enable Windows Firewall for all profiles"
          }
        }
      }
    } catch {}
  }

  # Check Windows Defender
  if (Test-Command "Get-MpComputerStatus") {
    try {
      $defender = Get-MpComputerStatus -ErrorAction Stop
      if (-not $defender.RealTimeProtectionEnabled) {
        $weaknesses += [pscustomobject]@{
          Category = "Antivirus"
          Issue = "Windows Defender Real-Time Protection is disabled"
          Risk = "Critical"
          Recommendation = "Enable Real-Time Protection immediately"
        }
      }
      if (-not $defender.AntivirusEnabled) {
        $weaknesses += [pscustomobject]@{
          Category = "Antivirus"
          Issue = "Windows Defender is disabled"
          Risk = "Critical"
          Recommendation = "Enable Windows Defender immediately"
        }
      }
    } catch {}
  }

  # Check Guest account
  if (Test-Command "Get-LocalUser") {
    try {
      $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
      if ($guest -and $guest.Enabled) {
        $weaknesses += [pscustomobject]@{
          Category = "User Accounts"
          Issue = "Guest account is enabled"
          Risk = "Medium"
          Recommendation = "Disable Guest account"
        }
      }
    } catch {}
  }

  return ,$weaknesses
}

# ---------------------------- Collection Functions ----------------------------

function Get-SystemSummary {
  $os = $null
  $cs = $null
  $bios = $null
  $cpu = $null
  $mem = $null

  try { 
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  } catch {
    Add-ErrorEntry -Function "Get-SystemSummary" -Error "Failed to get OS info: $_"
  }
  
  try { 
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  } catch {
    Add-ErrorEntry -Function "Get-SystemSummary" -Error "Failed to get computer system info: $_"
  }
  
  try { 
    $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
  } catch {
    Add-ErrorEntry -Function "Get-SystemSummary" -Error "Failed to get BIOS info: $_"
  }
  
  try { 
    $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop
  } catch {
    Add-ErrorEntry -Function "Get-SystemSummary" -Error "Failed to get CPU info: $_"
  }
  
  try { 
    $mem = Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop
  } catch {
    Add-ErrorEntry -Function "Get-SystemSummary" -Error "Failed to get memory info: $_"
  }

  $lastBoot = $null
  try {
    $lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
  } catch {}

  $installDate = $null
  try {
    $installDate = [Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate)
  } catch {}

  $uptimeHours = $null
  if ($lastBoot) {
    try {
      $uptimeHours = [math]::Round(((Get-Date) - $lastBoot).TotalHours, 2)
    } catch {}
  }

  $totalMemGB = $null
  try {
    $totalMemGB = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)
  } catch {}

  return [pscustomobject]@{
    ComputerName         = $env:COMPUTERNAME
    Domain               = $cs.Domain
    PartOfDomain         = $cs.PartOfDomain
    Manufacturer         = $cs.Manufacturer
    Model                = $cs.Model
    OSName               = $os.Caption
    OSVersion            = $os.Version
    OSBuildNumber        = $os.BuildNumber
    OSArchitecture       = $os.OSArchitecture
    InstallDate          = $installDate
    LastBootUpTime       = $lastBoot
    UptimeHours          = $uptimeHours
    BIOSVersion          = ($bios.SMBIOSBIOSVersion)
    BIOSSerial           = ($bios.SerialNumber)
    CPUName              = ($cpu | Select-Object -First 1 -ExpandProperty Name)
    CPUCores             = ($cpu | Measure-Object -Property NumberOfCores -Sum).Sum
    CPULogicalProcessors = ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    TotalMemoryGB        = $totalMemGB
    IsAdmin              = (Is-Admin)
    TimeCollected        = (Get-Date).ToString("o")
  }
}

function Get-StorageInfo {
  $disks = @()
  $vols  = @()

  try {
    $disks = Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Select-Object `
      Model, InterfaceType, MediaType, SerialNumber, Size, Partitions
  } catch {
    Add-ErrorEntry -Function "Get-StorageInfo" -Error "Failed to get disk info: $_"
  }

  try {
    $vols = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | Select-Object `
      DeviceID, VolumeName, FileSystem, Size, FreeSpace, DriveType
  } catch {
    Add-ErrorEntry -Function "Get-StorageInfo" -Error "Failed to get volume info: $_"
  }

  return [pscustomobject]@{
    Disks   = $disks
    Volumes = $vols
  }
}

function Get-NetworkInfo {
  $ipcfg = $null
  $adapters = @()
  $dns = @()
  $routesTxt = ""
  $arpTxt = ""

  if (Test-Command "Get-NetIPConfiguration") {
    try { 
      $ipcfg = Get-NetIPConfiguration -ErrorAction Stop
    } catch {
      Add-ErrorEntry -Function "Get-NetworkInfo" -Error "Failed to get NetIPConfiguration: $_"
    }
  }

  try {
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -ErrorAction Stop |
      Select-Object Description, MACAddress, DHCPEnabled, DHCPServer, IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder
  } catch {
    Add-ErrorEntry -Function "Get-NetworkInfo" -Error "Failed to get network adapters: $_"
  }

  if (Test-Command "Get-DnsClientServerAddress") {
    try { 
      $dns = Get-DnsClientServerAddress -ErrorAction Stop | 
        Select-Object InterfaceAlias, AddressFamily, ServerAddresses 
    } catch {
      Add-ErrorEntry -Function "Get-NetworkInfo" -Error "Failed to get DNS servers: $_"
    }
  }

  $routesTxt = (Invoke-ExeCapture -File "route" -Args @("print")).StdOut
  $arpTxt    = (Invoke-ExeCapture -File "arp"   -Args @("-a")).StdOut

  return [pscustomobject]@{
    NetIPConfigurationAvailable = [bool]$ipcfg
    NetIPConfiguration          = $ipcfg
    IPEnabledAdapters           = $adapters
    DnsClientServers            = $dns
    RoutesText                  = $routesTxt
    ArpText                     = $arpTxt
  }
}

function Get-DNSCache {
  $cache = @()

  if (Test-Command "Get-DnsClientCache") {
    try {
      $result = Get-DnsClientCache -ErrorAction Stop |
        Select-Object Entry, RecordName, RecordType, Data, TimeToLive
      if ($result) {
        $cache = @($result)
      }
    } catch {
      Add-ErrorEntry -Function "Get-DNSCache" -Error "Failed to get DNS cache: $_"
    }
  } else {
    $raw = (Invoke-ExeCapture -File "ipconfig" -Args @("/displaydns")).StdOut
    $cache = @([pscustomobject]@{ Note="ipconfig /displaydns raw"; Raw=$raw })
  }

  return ,$cache
}

function Get-OpenPortsAndNetstat {
  $tcp = @()
  $udp = @()
  $netstatTxt = ""

  if (Test-Command "Get-NetTCPConnection") {
    try {
      $tcp = Get-NetTCPConnection -ErrorAction Stop | Select-Object `
        LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    } catch {
      Add-ErrorEntry -Function "Get-OpenPortsAndNetstat" -Error "Failed to get TCP connections: $_"
    }
  } else {
    $netstatTxt = (Invoke-ExeCapture -File "netstat" -Args @("-ano")).StdOut
  }

  if (Test-Command "Get-NetUDPEndpoint") {
    try {
      $udp = Get-NetUDPEndpoint -ErrorAction Stop | Select-Object `
        LocalAddress, LocalPort, OwningProcess
    } catch {
      Add-ErrorEntry -Function "Get-OpenPortsAndNetstat" -Error "Failed to get UDP endpoints: $_"
    }
  }

  if (-not $netstatTxt) {
    $netstatTxt = (Invoke-ExeCapture -File "netstat" -Args @("-ano")).StdOut
  }

  return [pscustomobject]@{
    TcpConnections = $tcp
    UdpEndpoints   = $udp
    NetstatText    = $netstatTxt
  }
}

function Get-NetworkConnectionsEnhanced {
  $connections = @()
  
  if (Test-Command "Get-NetTCPConnection") {
    try {
      $allConnections = Get-NetTCPConnection -ErrorAction Stop | 
        Where-Object State -eq 'Established'
      
      foreach ($conn in $allConnections) {
        $proc = $null
        try {
          $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        } catch {}
        
        $connections += [pscustomobject]@{
          LocalAddress = $conn.LocalAddress
          LocalPort = $conn.LocalPort
          RemoteAddress = $conn.RemoteAddress
          RemotePort = $conn.RemotePort
          State = $conn.State
          ProcessId = $conn.OwningProcess
          ProcessName = if ($proc) { $proc.Name } else { $null }
          ProcessPath = if ($proc) { $proc.Path } else { $null }
        }
      }
    } catch {
      Add-ErrorEntry -Function "Get-NetworkConnectionsEnhanced" -Error "Failed to get enhanced connections: $_"
    }
  }
  
  return ,$connections
}

function Get-ServicesAndProcesses {
  $services = @()
  $processes = @()

  try {
    $services = Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object `
      Name, DisplayName, State, StartMode, StartName, PathName, ProcessId
  } catch {
    Add-ErrorEntry -Function "Get-ServicesAndProcesses" -Error "Failed to get services: $_"
  }

  try {
    $processes = Get-Process -ErrorAction Stop | Select-Object `
      Name, Id, CPU, WS, StartTime, Path, @{n='CommandLine';e={
        try {
          (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)" -ErrorAction SilentlyContinue).CommandLine
        } catch { $null }
      }}
  } catch {
    # Fallback to WMI
    try {
      $processes = Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object `
        Name, ProcessId, ExecutablePath, CommandLine, CreationDate
    } catch {
      Add-ErrorEntry -Function "Get-ServicesAndProcesses" -Error "Failed to get processes: $_"
    }
  }

  return [pscustomobject]@{
    Services  = $services
    Processes = $processes
  }
}

function Get-LocalUsersAndGroups {
  $users = @()
  $groups = @()
  $groupMembers = @()

  if (Test-Command "Get-LocalUser") {
    try { 
      $users = Get-LocalUser -ErrorAction Stop | 
        Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, UserMayChangePassword, Description 
    } catch {
      Add-ErrorEntry -Function "Get-LocalUsersAndGroups" -Error "Failed to get local users: $_"
    }
    
    try { 
      $groups = Get-LocalGroup -ErrorAction Stop | 
        Select-Object Name, Description 
    } catch {
      Add-ErrorEntry -Function "Get-LocalUsersAndGroups" -Error "Failed to get local groups: $_"
    }
    
    try {
      foreach ($g in (Get-LocalGroup -ErrorAction Stop)) {
        $m = @()
        try { 
          $m = Get-LocalGroupMember -Group $g.Name -ErrorAction Stop 
        } catch {}
        
        foreach ($mm in $m) {
          $groupMembers += [pscustomobject]@{ 
            Group = $g.Name
            Member = $mm.Name
            ObjectClass = $mm.ObjectClass
            PrincipalSource = $mm.PrincipalSource 
          }
        }
      }
    } catch {
      Add-ErrorEntry -Function "Get-LocalUsersAndGroups" -Error "Failed to get group members: $_"
    }
  } else {
    # Fallback for older OS: ADSI
    try {
      $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
      foreach ($child in $adsi.Children) {
        if ($child.SchemaClassName -eq "User") {
          $users += [pscustomobject]@{
            Name        = $child.Name
            Enabled     = (try { -not [bool]$child.AccountDisabled } catch { $null })
            Description = (try { $child.Description } catch { $null })
          }
        }
        if ($child.SchemaClassName -eq "Group") {
          $groups += [pscustomobject]@{
            Name        = $child.Name
            Description = (try { $child.Description } catch { $null })
          }
        }
      }
      
      foreach ($g in $groups) {
        try {
          $grp = [ADSI]"WinNT://$env:COMPUTERNAME/$($g.Name),group"
          $members = @($grp.psbase.Invoke("Members"))
          foreach ($m in $members) {
            $name = $m.GetType().InvokeMember("Name",'GetProperty',$null,$m,$null)
            $groupMembers += [pscustomobject]@{ 
              Group = $g.Name
              Member = $name
              ObjectClass = "Unknown"
              PrincipalSource = "WinNT" 
            }
          }
        } catch {}
      }
    } catch {
      Add-ErrorEntry -Function "Get-LocalUsersAndGroups" -Error "Failed to enumerate via ADSI: $_"
    }
  }

  return [pscustomobject]@{
    Users        = $users
    Groups       = $groups
    GroupMembers = $groupMembers
  }
}

function Get-ScheduledTasksInfo {
  $tasks = @()

  if (Test-Command "Get-ScheduledTask") {
    try {
      $tasks = Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        $info = $null
        try {
          $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
        } catch {}

        # Pre-calculate values to avoid inline if statements
        $lastRunTime = if ($info) { $info.LastRunTime } else { $null }
        $nextRunTime = if ($info) { $info.NextRunTime } else { $null }
        $lastTaskResult = if ($info) { $info.LastTaskResult } else { $null }

        # Safely format actions
        $actionsText = ""
        if ($_.Actions) {
          $actionsText = (($_.Actions | ForEach-Object {
            if (-not $_) { return "" }
            try {
              $exe = if ($_.PSObject.Properties['Execute']) { $_.Execute } else { "" }
              $args = if ($_.PSObject.Properties['Arguments']) { $_.Arguments } else { "" }
              if ($exe) {
                "$exe $args".Trim()
              } else {
                try { $_.ToString() } catch { "" }
              }
            } catch {
              try { if ($_) { $_.ToString() } else { "" } } catch { "" }
            }
          }) -join "; ")
        }

        [pscustomobject]@{
          TaskName     = $_.TaskName
          TaskPath     = $_.TaskPath
          State        = $_.State
          Author       = $_.Author
          Description  = $_.Description
          Actions      = $actionsText
          Triggers     = (($_.Triggers | ForEach-Object {
            if (-not $_) { return "" }
            try { $_.ToString() } catch { "" }
          }) -join "; ")
          LastRunTime  = $lastRunTime
          NextRunTime  = $nextRunTime
          LastTaskResult = $lastTaskResult
        }
      }
    } catch {
      Add-ErrorEntry -Function "Get-ScheduledTasksInfo" -Error "Failed to get scheduled tasks: $_"
    }
  } else {
    # Fallback: schtasks verbose CSV
    $raw = (Invoke-ExeCapture -File "schtasks.exe" -Args @("/query","/fo","csv","/v")).StdOut
    try {
      $tasks = $raw | ConvertFrom-Csv | Select-Object `
        "TaskName","Status","Author","Task To Run","Start In","Schedule Type",
        "Start Time","Start Date","End Date","Days","Months","Next Run Time",
        "Last Run Time","Last Result","Run As User"
    } catch {
      $tasks = @([pscustomobject]@{ 
        Note="schtasks output not parsed"
        Raw=$raw 
      })
      Add-ErrorEntry -Function "Get-ScheduledTasksInfo" -Error "Failed to parse schtasks output"
    }
  }

  return ,$tasks
}

function Get-AutorunsInfo {
  $autoruns = @()
  
  # Startup folders
  $paths = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
  )
  
  foreach ($p in $paths) {
    if (Test-Path $p) {
      try {
        $items = Get-ChildItem $p -ErrorAction Stop
        foreach ($item in $items) {
          $autoruns += [pscustomobject]@{
            Location = $p
            Type = "StartupFolder"
            Name = $item.Name
            Value = $item.FullName
            CreationTime = $item.CreationTime
            LastWriteTime = $item.LastWriteTime
            Hash = (Get-FileHashSafe $item.FullName)
          }
        }
      } catch {}
    }
  }
  
  # Registry Run keys
  $runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
  )
  
  foreach ($k in $runKeys) {
    try {
      if (Test-Path $k) {
        $props = Get-ItemProperty $k -ErrorAction Stop
        $props.PSObject.Properties | Where-Object { 
          $_.Name -notlike 'PS*' 
        } | ForEach-Object {
          $autoruns += [pscustomobject]@{
            Location = $k
            Type = "Registry"
            Name = $_.Name
            Value = $_.Value
            CreationTime = $null
            LastWriteTime = $null
            Hash = $null
          }
        }
      }
    } catch {}
  }
  
  return ,$autoruns
}

function Get-PersistenceLocations {
  $wmiEvents = @()
  $suspiciousServices = @()
  
  # WMI Event Consumers (common persistence)
  try {
    $wmiEvents = Get-CimInstance -Namespace "root/subscription" -ClassName "__EventFilter" -ErrorAction Stop |
      Select-Object Name, Query, EventNamespace
  } catch {
    Add-ErrorEntry -Function "Get-PersistenceLocations" -Error "Failed to get WMI event filters: $_"
  }
  
  # Services with suspicious paths
  try {
    $suspiciousServices = Get-CimInstance Win32_Service -ErrorAction Stop | 
      Where-Object { 
        $_.PathName -match '(temp|appdata|public|programdata|users)' -and 
        $_.StartMode -eq 'Auto' 
      } | Select-Object Name, DisplayName, PathName, StartMode, State, StartName
  } catch {
    Add-ErrorEntry -Function "Get-PersistenceLocations" -Error "Failed to check suspicious services: $_"
  }
  
  return [pscustomobject]@{
    WMIEventFilters = $wmiEvents
    SuspiciousServices = $suspiciousServices
  }
}

function Get-InstalledSoftware {
  $sw = @()

  # Registry-based uninstall keys (64-bit and 32-bit)
  $paths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )

  foreach ($p in $paths) {
    try {
      $items = Get-ItemProperty $p -ErrorAction SilentlyContinue
      foreach ($i in $items) {
        if ([string]::IsNullOrWhiteSpace($i.DisplayName)) { continue }
        $sw += [pscustomobject]@{
          DisplayName     = $i.DisplayName
          DisplayVersion  = $i.DisplayVersion
          Publisher       = $i.Publisher
          InstallDate     = $i.InstallDate
          InstallLocation = $i.InstallLocation
          UninstallString = $i.UninstallString
          Source          = $p.Replace("\*","")
        }
      }
    } catch {}
  }

  # AppX packages (optional; can be large)
  $appx = @()
  if (-not $Quick -and (Test-Command "Get-AppxPackage")) {
    try {
      $appx = Get-AppxPackage -ErrorAction Stop | 
        Select-Object Name, PackageFullName, Publisher, Version, InstallLocation
    } catch {
      Add-ErrorEntry -Function "Get-InstalledSoftware" -Error "Failed to get AppX packages: $_"
    }
  }

  return [pscustomobject]@{
    UninstallRegistry = $sw
    AppxPackages      = $appx
  }
}

function Get-PatchInfo {
  $hotfix = @()
  try {
    $hotfix = Get-HotFix -ErrorAction Stop | 
      Select-Object HotFixID, Description, InstalledBy, InstalledOn
  } catch {
    Add-ErrorEntry -Function "Get-PatchInfo" -Error "Failed to get hotfix info: $_"
  }
  return ,$hotfix
}

function Get-FirewallInfo {
  $rules = @()
  $profiles = @()
  $raw = ""

  if (Test-Command "Get-NetFirewallRule") {
    try {
      $profiles = Get-NetFirewallProfile -ErrorAction Stop | 
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, 
          NotifyOnListen, AllowInboundRules, AllowLocalFirewallRules
    } catch {
      Add-ErrorEntry -Function "Get-FirewallInfo" -Error "Failed to get firewall profiles: $_"
    }
    
    try {
      $rules = Get-NetFirewallRule -ErrorAction Stop | 
        Select-Object DisplayName, Enabled, Direction, Action, Profile, 
          Group, PolicyStoreSource, Owner
    } catch {
      Add-ErrorEntry -Function "Get-FirewallInfo" -Error "Failed to get firewall rules: $_"
    }
  } else {
    $raw = (Invoke-ExeCapture -File "netsh" -Args @("advfirewall","firewall","show","rule","name=all")).StdOut
  }

  return [pscustomobject]@{
    Profiles     = $profiles
    Rules        = $rules
    NetshRawText = $raw
  }
}

function Get-SecurityPosture {
  # Defender (if present)
  $def = $null
  if (Test-Command "Get-MpComputerStatus") {
    try { 
      $def = Get-MpComputerStatus -ErrorAction Stop
    } catch {
      Add-ErrorEntry -Function "Get-SecurityPosture" -Error "Failed to get Defender status: $_"
    }
  }

  # Security Center AV products
  $av = @()
  try {
    $av = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop |
      Select-Object displayName, pathToSignedProductExe, productState, timestamp
  } catch {
    # Might not exist on servers or older systems
  }

  # UAC settings
  $uac = [pscustomobject]@{
    EnableLUA                 = Get-RegistryValueSafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
    ConsentPromptBehaviorAdmin= Get-RegistryValueSafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin"
    PromptOnSecureDesktop     = Get-RegistryValueSafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop"
  }

  # RDP status
  $rdpDeny = Get-RegistryValueSafe "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"

  # SMB settings
  $smb1 = $null
  $smbSrv = $null
  if (Test-Command "Get-SmbServerConfiguration") {
    try { 
      $smbSrv = Get-SmbServerConfiguration -ErrorAction Stop | 
        Select-Object EnableSMB1Protocol, EnableSMB2Protocol, RejectUnencryptedAccess, 
          RequireSecuritySignature, EncryptData 
    } catch {
      Add-ErrorEntry -Function "Get-SecurityPosture" -Error "Failed to get SMB config: $_"
    }
  } else {
    $smb1 = Get-RegistryValueSafe "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"
  }

  # BitLocker status
  $bitlocker = @()
  if (Test-Command "Get-BitLockerVolume") {
    try { 
      $bitlocker = Get-BitLockerVolume -ErrorAction Stop | 
        Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, KeyProtector 
    } catch {
      Add-ErrorEntry -Function "Get-SecurityPosture" -Error "Failed to get BitLocker status: $_"
    }
  } else {
    $mb = (Invoke-ExeCapture -File "manage-bde.exe" -Args @("-status")).StdOut
    if ($mb) { 
      $bitlocker = @([pscustomobject]@{ 
        Note="manage-bde -status"
        Raw=$mb 
      }) 
    }
  }

  return [pscustomobject]@{
    DefenderStatus = $def
    SecurityCenterAV = $av
    UAC = $uac
    RDP_DenyTSConnections = $rdpDeny
    SMB_ServerConfiguration = $smbSrv
    SMB1_RegistryFallback = $smb1
    BitLocker = $bitlocker
  }
}

function Get-SharesInfo {
  $shares = @()
  if (Test-Command "Get-SmbShare") {
    try { 
      $shares = Get-SmbShare -ErrorAction Stop | 
        Select-Object Name, Path, Description, ScopeName, EncryptData, 
          FolderEnumerationMode, CachingMode 
    } catch {
      Add-ErrorEntry -Function "Get-SharesInfo" -Error "Failed to get SMB shares: $_"
    }
  } else {
    $raw = (Invoke-ExeCapture -File "net" -Args @("share")).StdOut
    $shares = @([pscustomobject]@{ 
      Note="net share raw"
      Raw=$raw 
    })
  }
  return ,$shares
}

function Get-CertificatesLocalMachine {
  $certs = @()
  try {
    $stores = @("My","Root","CA","AuthRoot","TrustedPublisher","TrustedPeople")
    foreach ($s in $stores) {
      $path = "Cert:\LocalMachine\$s"
      if (Test-Path $path) {
        $storeCerts = Get-ChildItem $path -ErrorAction Stop
        foreach ($cert in $storeCerts) {
          $certs += [pscustomobject]@{
            Store = $s
            Subject = $cert.Subject
            Issuer = $cert.Issuer
            Thumbprint = $cert.Thumbprint
            NotBefore = $cert.NotBefore
            NotAfter = $cert.NotAfter
            HasPrivateKey = $cert.HasPrivateKey
            SerialNumber = $cert.SerialNumber
          }
        }
      }
    }
  } catch {
    Add-ErrorEntry -Function "Get-CertificatesLocalMachine" -Error "Failed to get certificates: $_"
  }
  return ,$certs
}

function Get-CriticalFileHashes {
  $criticalFiles = @(
    "$env:SystemRoot\System32\drivers\etc\hosts",
    "$env:SystemRoot\System32\drivers\etc\networks",
    "$env:SystemRoot\System32\drivers\etc\protocol",
    "$env:SystemRoot\System32\drivers\etc\services"
  )
  
  $hashes = @()
  foreach ($file in $criticalFiles) {
    if (Test-Path $file) {
      try {
        $item = Get-Item $file -ErrorAction Stop
        $hashes += [pscustomobject]@{
          File = $file
          SHA256 = (Get-FileHashSafe $file)
          LastModified = $item.LastWriteTime
          Size = $item.Length
        }
      } catch {}
    }
  }
  
  return ,$hashes
}

function Get-EventLogSummary24h {
  $since = (Get-Date).AddHours(-24)

  $summaries = @()
  foreach ($log in @("System","Security")) {
    try {
      $events = Get-WinEvent -FilterHashtable @{ 
        LogName=$log
        StartTime=$since 
      } -ErrorAction Stop
      
      $summaries += [pscustomobject]@{
        LogName = $log
        Since  = $since
        Total  = $events.Count
        Critical = ($events | Where-Object LevelDisplayName -eq "Critical").Count
        Error    = ($events | Where-Object LevelDisplayName -eq "Error").Count
        Warning  = ($events | Where-Object LevelDisplayName -eq "Warning").Count
        TopEventIDs = (($events | Group-Object Id | Sort-Object Count -Descending | 
          Select-Object -First 10 | ForEach-Object { 
            "$($_.Name):$($_.Count)" 
          }) -join ", ")
      }
    } catch {
      $summaries += [pscustomobject]@{ 
        LogName=$log
        Since=$since
        Note="Unable to read log (need admin rights or log unavailable)"
        Error=$_.Exception.Message 
      }
    }
  }
  return ,$summaries
}

# ---------------------------- Main Execution ----------------------------

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Windows Inventory Collection v2.0" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Memory optimization
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

$reportDir = New-ReportFolder -Root $OutputRoot
$csvDir    = Join-Path $reportDir "csv"
$artDir    = Join-Path $reportDir "artifacts"

Write-LogEntry "Starting inventory collection" -Level "INFO"
Write-LogEntry "Output directory: $reportDir"
Write-LogEntry "Running as Administrator: $(Is-Admin)"

$inventory = [ordered]@{
  Metadata = [ordered]@{
    ScriptName       = "Get-WindowsInventory.ps1"
    Version          = "2.1-CCDC"
    QuickMode        = [bool]$Quick
    IncludeEventLogs = [bool]$IncludeEventLogs
    CollectedAt      = (Get-Date).ToString("o")
    OutputDir        = $reportDir
    IsAdmin          = (Is-Admin)
    ExecutionTime    = [ordered]@{
      Start = $script:StartTime
      End = $null
      DurationSeconds = $null
    }
  }
  System     = $null
  Storage    = $null
  Network    = $null
  DNSCache   = [ordered]@{ Csv = $null; Count = 0 }
  Ports      = $null
  EstablishedConnections = [ordered]@{ Csv = $null; Count = 0 }
  Services   = [ordered]@{ Csv = $null; Count = 0 }
  Processes  = [ordered]@{ Csv = $null; Count = 0 }
  Users      = [ordered]@{ UsersCsv = $null; GroupsCsv = $null; MembersCsv = $null }
  Tasks      = [ordered]@{ Csv = $null; Count = 0 }
  Autoruns   = [ordered]@{ Csv = $null; Count = 0 }
  Persistence= $null
  Software   = [ordered]@{ UninstallCsv = $null; AppxCsv = $null; Count = 0 }
  Patches    = [ordered]@{ Csv = $null; Count = 0 }
  Firewall   = [ordered]@{ ProfilesCsv = $null; RulesCsv = $null; NetshText = $null }
  Shares     = [ordered]@{ Csv = $null; Count = 0 }
  Certs      = [ordered]@{ Csv = $null; Count = 0 }
  Security   = $null
  CriticalFiles = [ordered]@{ Csv = $null; Count = 0 }
  Artifacts  = [ordered]@{}
  FileHashes = [ordered]@{}
  ThreatAnalysis = [ordered]@{
    SuspiciousProcesses = [ordered]@{ Csv = $null; Count = 0 }
    SuspiciousServices = [ordered]@{ Csv = $null; Count = 0 }
    SuspiciousTasks = [ordered]@{ Csv = $null; Count = 0 }
    SuspiciousConnections = [ordered]@{ Csv = $null; Count = 0 }
    UnauthorizedAdmins = [ordered]@{ Csv = $null; Count = 0 }
    SecurityWeaknesses = [ordered]@{ Csv = $null; Count = 0 }
    RecentModifications = [ordered]@{ Csv = $null; Count = 0 }
  }
}

# Step 1: System Summary
Update-Progress "Collecting system summary..."
Write-LogEntry "Collecting system summary"
$inventory.System = Get-SystemSummary

# Step 2: Storage
Update-Progress "Collecting storage information..."
Write-LogEntry "Collecting storage"
$inventory.Storage = Get-StorageInfo

# Step 3: Network
Update-Progress "Collecting network configuration..."
Write-LogEntry "Collecting network"
$net = Get-NetworkInfo
$inventory.Network = [pscustomobject]@{
  NetIPConfigurationAvailable = $net.NetIPConfigurationAvailable
  IPEnabledAdapterCount       = ($net.IPEnabledAdapters | Measure-Object).Count
  DnsEntryCount               = ($net.DnsClientServers | Measure-Object).Count
}

$routePath = Join-Path $artDir "route_print.txt"
$arpPath   = Join-Path $artDir "arp_a.txt"
Write-TextFile -Path $routePath -Content $net.RoutesText
Write-TextFile -Path $arpPath   -Content $net.ArpText
$inventory.Artifacts.Routes = $routePath
$inventory.Artifacts.Arp    = $arpPath

$ipJsonPath = Join-Path $artDir "network_ipenabled_adapters.json"
try { 
  ($net.IPEnabledAdapters | ConvertTo-Json -Depth 6) | 
    Out-File $ipJsonPath -Encoding UTF8 -Force 
} catch {}
$inventory.Artifacts.IPEnabledAdapters = $ipJsonPath

$dnsJsonPath = Join-Path $artDir "network_dns_servers.json"
try { 
  ($net.DnsClientServers | ConvertTo-Json -Depth 6) | 
    Out-File $dnsJsonPath -Encoding UTF8 -Force 
} catch {}
$inventory.Artifacts.DnsServers = $dnsJsonPath

# Step 4: DNS Cache
Update-Progress "Collecting DNS cache..."
Write-LogEntry "Collecting DNS cache"
$dnsCache = Get-DNSCache
$dnsCacheCsv = Join-Path $csvDir "dns_cache.csv"
Export-CsvSafe -Data $dnsCache -Path $dnsCacheCsv
$inventory.DNSCache.Csv = $dnsCacheCsv
$inventory.DNSCache.Count = ($dnsCache | Measure-Object).Count

# Step 5: Ports and Netstat
Update-Progress "Collecting open ports and network connections..."
Write-LogEntry "Collecting ports/netstat"
$ports = Get-OpenPortsAndNetstat
$inventory.Ports = [pscustomobject]@{
  TcpCount = ($ports.TcpConnections | Measure-Object).Count
  UdpCount = ($ports.UdpEndpoints   | Measure-Object).Count
}

$netstatPath = Join-Path $artDir "netstat_ano.txt"
Write-TextFile -Path $netstatPath -Content $ports.NetstatText
$inventory.Artifacts.Netstat = $netstatPath

if ($ports.TcpConnections.Count -gt 0) {
  $tcpCsv = Join-Path $csvDir "tcp_connections.csv"
  Export-CsvSafe -Data $ports.TcpConnections -Path $tcpCsv
  $inventory.Artifacts.TcpConnectionsCsv = $tcpCsv
}

if ($ports.UdpEndpoints.Count -gt 0) {
  $udpCsv = Join-Path $csvDir "udp_endpoints.csv"
  Export-CsvSafe -Data $ports.UdpEndpoints -Path $udpCsv
  $inventory.Artifacts.UdpEndpointsCsv = $udpCsv
}

# Step 6: Enhanced Network Connections
Update-Progress "Mapping established connections to processes..."
Write-LogEntry "Collecting enhanced network connections"
$enhancedConns = Get-NetworkConnectionsEnhanced
if ($enhancedConns.Count -gt 0) {
  $connCsv = Join-Path $csvDir "established_connections_with_processes.csv"
  Export-CsvSafe -Data $enhancedConns -Path $connCsv
  $inventory.EstablishedConnections.Csv = $connCsv
  $inventory.EstablishedConnections.Count = ($enhancedConns | Measure-Object).Count
}

# Step 7: Services and Processes
Update-Progress "Collecting services and processes..."
Write-LogEntry "Collecting services/processes"
$sp = Get-ServicesAndProcesses
$svcCsv = Join-Path $csvDir "services.csv"
$procCsv = Join-Path $csvDir "processes.csv"
Export-CsvSafe -Data $sp.Services  -Path $svcCsv
Export-CsvSafe -Data $sp.Processes -Path $procCsv
$inventory.Services.Csv = $svcCsv
$inventory.Services.Count = ($sp.Services | Measure-Object).Count
$inventory.Processes.Csv = $procCsv
$inventory.Processes.Count = ($sp.Processes | Measure-Object).Count

# Step 8: Local Users and Groups
Update-Progress "Collecting local users and groups..."
Write-LogEntry "Collecting local users/groups"
$ug = Get-LocalUsersAndGroups
$usersCsv   = Join-Path $csvDir "local_users.csv"
$groupsCsv  = Join-Path $csvDir "local_groups.csv"
$membersCsv = Join-Path $csvDir "local_group_members.csv"
Export-CsvSafe -Data $ug.Users        -Path $usersCsv
Export-CsvSafe -Data $ug.Groups       -Path $groupsCsv
Export-CsvSafe -Data $ug.GroupMembers -Path $membersCsv
$inventory.Users.UsersCsv   = $usersCsv
$inventory.Users.GroupsCsv  = $groupsCsv
$inventory.Users.MembersCsv = $membersCsv

# Step 9: Scheduled Tasks
Update-Progress "Collecting scheduled tasks..."
Write-LogEntry "Collecting scheduled tasks"
$tasks = Get-ScheduledTasksInfo
$tasksCsv = Join-Path $csvDir "scheduled_tasks.csv"
Export-CsvSafe -Data $tasks -Path $tasksCsv
$inventory.Tasks.Csv = $tasksCsv
$inventory.Tasks.Count = ($tasks | Measure-Object).Count

# Step 10: Autoruns
Update-Progress "Collecting autorun locations..."
Write-LogEntry "Collecting autoruns"
$autoruns = Get-AutorunsInfo
$autorunsCsv = Join-Path $csvDir "autoruns.csv"
Export-CsvSafe -Data $autoruns -Path $autorunsCsv
$inventory.Autoruns.Csv = $autorunsCsv
$inventory.Autoruns.Count = ($autoruns | Measure-Object).Count

# Step 11: Persistence Locations
Update-Progress "Checking persistence mechanisms..."
Write-LogEntry "Collecting persistence locations"
$inventory.Persistence = Get-PersistenceLocations
$wmiCsv = Join-Path $csvDir "wmi_event_filters.csv"
$suspSvcCsv = Join-Path $csvDir "suspicious_services.csv"
Export-CsvSafe -Data $inventory.Persistence.WMIEventFilters -Path $wmiCsv
Export-CsvSafe -Data $inventory.Persistence.SuspiciousServices -Path $suspSvcCsv
$inventory.Artifacts.WMIEventFiltersCsv = $wmiCsv
$inventory.Artifacts.SuspiciousServicesCsv = $suspSvcCsv

# Step 12: Security Posture
Update-Progress "Collecting security posture..."
Write-LogEntry "Collecting security posture"
$inventory.Security = Get-SecurityPosture

# Step 13: Patches
Update-Progress "Collecting installed patches..."
Write-LogEntry "Collecting patches"
$patches = Get-PatchInfo
$patchCsv = Join-Path $csvDir "patches_hotfix.csv"
Export-CsvSafe -Data $patches -Path $patchCsv
$inventory.Patches.Csv = $patchCsv
$inventory.Patches.Count = ($patches | Measure-Object).Count

# Step 14: Software
if ($Software -and -not $Quick) {
  Update-Progress "Collecting installed software (full)..."
  Write-LogEntry "Collecting installed software (full)"
  $soft = Get-InstalledSoftware
  $swCsv = Join-Path $csvDir "installed_software_registry.csv"
  Export-CsvSafe -Data $soft.UninstallRegistry -Path $swCsv
  $inventory.Software.UninstallCsv = $swCsv
  $inventory.Software.Count = ($soft.UninstallRegistry | Measure-Object).Count

  if ($soft.AppxPackages.Count -gt 0) {
    $appxCsv = Join-Path $csvDir "installed_software_appx.csv"
    Export-CsvSafe -Data $soft.AppxPackages -Path $appxCsv
    $inventory.Software.AppxCsv = $appxCsv
  }
} elseif ($Software -and $Quick) {
  Update-Progress "Collecting installed software (quick)..."
  Write-LogEntry "Collecting installed software (quick: registry only)"
  $soft = Get-InstalledSoftware
  $swCsv = Join-Path $csvDir "installed_software_registry.csv"
  Export-CsvSafe -Data $soft.UninstallRegistry -Path $swCsv
  $inventory.Software.UninstallCsv = $swCsv
  $inventory.Software.Count = ($soft.UninstallRegistry | Measure-Object).Count
}

# Step 15: Firewall
if ($Firewall -and -not $Quick) {
  Update-Progress "Collecting firewall configuration (full)..."
  Write-LogEntry "Collecting firewall profiles/rules (full)"
  $fw = Get-FirewallInfo
  
  if ($fw.Profiles.Count -gt 0) {
    $fwProfCsv = Join-Path $csvDir "firewall_profiles.csv"
    Export-CsvSafe -Data $fw.Profiles -Path $fwProfCsv
    $inventory.Firewall.ProfilesCsv = $fwProfCsv
  }
  
  if ($fw.Rules.Count -gt 0) {
    $fwRulesCsv = Join-Path $csvDir "firewall_rules.csv"
    Export-CsvSafe -Data $fw.Rules -Path $fwRulesCsv
    $inventory.Firewall.RulesCsv = $fwRulesCsv
  }
  
  if ($fw.NetshRawText) {
    $fwTxt = Join-Path $artDir "firewall_netsh_rules.txt"
    Write-TextFile -Path $fwTxt -Content $fw.NetshRawText
    $inventory.Firewall.NetshText = $fwTxt
  }
} elseif ($Firewall -and $Quick) {
  Update-Progress "Collecting firewall profiles (quick)..."
  Write-LogEntry "Collecting firewall profiles (quick)"
  $fw = Get-FirewallInfo
  
  if ($fw.Profiles.Count -gt 0) {
    $fwProfCsv = Join-Path $csvDir "firewall_profiles.csv"
    Export-CsvSafe -Data $fw.Profiles -Path $fwProfCsv
    $inventory.Firewall.ProfilesCsv = $fwProfCsv
  }
}

# Step 16: Shares
Update-Progress "Collecting network shares..."
Write-LogEntry "Collecting shares"
$shares = Get-SharesInfo
$sharesCsv = Join-Path $csvDir "shares.csv"
Export-CsvSafe -Data $shares -Path $sharesCsv
$inventory.Shares.Csv = $sharesCsv
$inventory.Shares.Count = ($shares | Measure-Object).Count

# Step 17: Certificates
if ($Certs -and -not $Quick) {
  Update-Progress "Collecting LocalMachine certificates..."
  Write-LogEntry "Collecting LocalMachine certificates"
  $certList = Get-CertificatesLocalMachine
  $certCsv = Join-Path $csvDir "certificates_localmachine.csv"
  Export-CsvSafe -Data $certList -Path $certCsv
  $inventory.Certs.Csv = $certCsv
  $inventory.Certs.Count = ($certList | Measure-Object).Count
}

# Step 18: Critical File Hashes
Update-Progress "Hashing critical system files..."
Write-LogEntry "Collecting critical file hashes"
$criticalHashes = Get-CriticalFileHashes
$critHashCsv = Join-Path $csvDir "critical_file_hashes.csv"
Export-CsvSafe -Data $criticalHashes -Path $critHashCsv
$inventory.CriticalFiles.Csv = $critHashCsv
$inventory.CriticalFiles.Count = ($criticalHashes | Measure-Object).Count

# Step 19: Event Logs (Optional)
if ($IncludeEventLogs) {
  Update-Progress "Collecting event log summary..."
  Write-LogEntry "Collecting event log summary (last 24h)"
  $ev = Get-EventLogSummary24h
  $evCsv = Join-Path $csvDir "eventlog_summary_24h.csv"
  Export-CsvSafe -Data $ev -Path $evCsv
  $inventory.Artifacts.EventLogSummary24h = $evCsv
}

# Step 20: CCDC Threat Analysis - Suspicious Processes
Update-Progress "Analyzing processes for threats..."
Write-LogEntry "Running threat analysis on processes"
$suspiciousProcs = @()
foreach ($proc in $sp.Processes) {
  $findings = Test-SuspiciousProcess -Process $proc
  if ($findings.Count -gt 0) {
    $suspiciousProcs += [pscustomobject]@{
      Name = $proc.Name
      Id = $proc.Id
      Path = if ($proc.Path) { $proc.Path } else { $proc.ExecutablePath }
      CommandLine = $proc.CommandLine
      Findings = ($findings -join "; ")
    }
  }
}
if ($suspiciousProcs.Count -gt 0) {
  $suspProcCsv = Join-Path $csvDir "threat_suspicious_processes.csv"
  Export-CsvSafe -Data $suspiciousProcs -Path $suspProcCsv
  $inventory.ThreatAnalysis.SuspiciousProcesses.Csv = $suspProcCsv
  $inventory.ThreatAnalysis.SuspiciousProcesses.Count = $suspiciousProcs.Count
  Write-LogEntry "Found $($suspiciousProcs.Count) suspicious processes" -Level "WARN"
}

# Step 21: CCDC Threat Analysis - Suspicious Services
Update-Progress "Analyzing services for threats..."
Write-LogEntry "Running threat analysis on services"
$suspiciousServices = @()
foreach ($svc in $sp.Services) {
  $findings = Test-SuspiciousService -Service $svc
  if ($findings.Count -gt 0) {
    $suspiciousServices += [pscustomobject]@{
      Name = $svc.Name
      DisplayName = $svc.DisplayName
      State = $svc.State
      StartMode = $svc.StartMode
      PathName = $svc.PathName
      StartName = $svc.StartName
      Findings = ($findings -join "; ")
    }
  }
}
if ($suspiciousServices.Count -gt 0) {
  $suspSvcCsv = Join-Path $csvDir "threat_suspicious_services.csv"
  Export-CsvSafe -Data $suspiciousServices -Path $suspSvcCsv
  $inventory.ThreatAnalysis.SuspiciousServices.Csv = $suspSvcCsv
  $inventory.ThreatAnalysis.SuspiciousServices.Count = $suspiciousServices.Count
  Write-LogEntry "Found $($suspiciousServices.Count) suspicious services" -Level "WARN"
}

# Step 22: CCDC Threat Analysis - Suspicious Scheduled Tasks
Update-Progress "Analyzing scheduled tasks for threats..."
Write-LogEntry "Running threat analysis on scheduled tasks"
$suspiciousTasks = @()
foreach ($task in $tasks) {
  $findings = Test-SuspiciousScheduledTask -Task $task
  if ($findings.Count -gt 0) {
    $suspiciousTasks += [pscustomobject]@{
      TaskName = $task.TaskName
      TaskPath = $task.TaskPath
      State = $task.State
      Author = $task.Author
      Actions = $task.Actions
      Findings = ($findings -join "; ")
    }
  }
}
if ($suspiciousTasks.Count -gt 0) {
  $suspTaskCsv = Join-Path $csvDir "threat_suspicious_tasks.csv"
  Export-CsvSafe -Data $suspiciousTasks -Path $suspTaskCsv
  $inventory.ThreatAnalysis.SuspiciousTasks.Csv = $suspTaskCsv
  $inventory.ThreatAnalysis.SuspiciousTasks.Count = $suspiciousTasks.Count
  Write-LogEntry "Found $($suspiciousTasks.Count) suspicious scheduled tasks" -Level "WARN"
}

# Step 23: CCDC Threat Analysis - Suspicious Network Connections
Update-Progress "Analyzing network connections for threats..."
Write-LogEntry "Running threat analysis on network connections"
if ($enhancedConns.Count -gt 0) {
  $suspConns = Get-SuspiciousNetworkConnections -Connections $enhancedConns
  if ($suspConns.Count -gt 0) {
    $suspConnCsv = Join-Path $csvDir "threat_suspicious_connections.csv"
    Export-CsvSafe -Data $suspConns -Path $suspConnCsv
    $inventory.ThreatAnalysis.SuspiciousConnections.Csv = $suspConnCsv
    $inventory.ThreatAnalysis.SuspiciousConnections.Count = $suspConns.Count
    Write-LogEntry "Found $($suspConns.Count) suspicious network connections" -Level "WARN"
  }
}

# Step 24: CCDC Threat Analysis - Unauthorized Administrators
Update-Progress "Checking for unauthorized administrators..."
Write-LogEntry "Checking for unauthorized administrators"
$unauthorizedAdmins = @()
foreach ($member in $ug.GroupMembers) {
  if (Test-UnauthorizedAdmin -GroupMember $member) {
    $unauthorizedAdmins += $member
  }
}
if ($unauthorizedAdmins.Count -gt 0) {
  $unauthAdminCsv = Join-Path $csvDir "threat_unauthorized_admins.csv"
  Export-CsvSafe -Data $unauthorizedAdmins -Path $unauthAdminCsv
  $inventory.ThreatAnalysis.UnauthorizedAdmins.Csv = $unauthAdminCsv
  $inventory.ThreatAnalysis.UnauthorizedAdmins.Count = $unauthorizedAdmins.Count
  Write-LogEntry "Found $($unauthorizedAdmins.Count) potentially unauthorized administrators" -Level "WARN"
}

# Step 25: CCDC Security Weaknesses and Recent Modifications
Update-Progress "Checking security configuration weaknesses..."
Write-LogEntry "Checking security configuration weaknesses"
$secWeaknesses = Get-SecurityWeaknesses
if ($secWeaknesses.Count -gt 0) {
  $weaknessCsv = Join-Path $csvDir "security_weaknesses.csv"
  Export-CsvSafe -Data $secWeaknesses -Path $weaknessCsv
  $inventory.ThreatAnalysis.SecurityWeaknesses.Csv = $weaknessCsv
  $inventory.ThreatAnalysis.SecurityWeaknesses.Count = $secWeaknesses.Count
  Write-LogEntry "Found $($secWeaknesses.Count) security weaknesses" -Level "WARN"

  # Log critical weaknesses to console
  $critical = @($secWeaknesses | Where-Object { $_.Risk -eq 'Critical' })
  if ($critical.Count -gt 0) {
    Write-LogEntry "CRITICAL: $($critical.Count) critical security issues found!" -Level "ERROR"
  }
}

Write-LogEntry "Checking for recent system file modifications (last 24h)"
$recentMods = Get-RecentFileModifications -Hours 24
if ($recentMods -and $recentMods.Count -gt 0) {
  $recentModCsv = Join-Path $csvDir "recent_system_modifications_24h.csv"
  Export-CsvSafe -Data $recentMods -Path $recentModCsv
  $inventory.ThreatAnalysis.RecentModifications.Csv = $recentModCsv
  $inventory.ThreatAnalysis.RecentModifications.Count = $recentMods.Count
  Write-LogEntry "Found $($recentMods.Count) recent modifications to system directories" -Level "INFO"
}

# Step 26: Additional Baseline Artifacts
Update-Progress "Collecting baseline text artifacts..."
Write-LogEntry "Collecting baseline text artifacts"
$sysinfoPath = Join-Path $artDir "systeminfo.txt"
$ipconfigPath = Join-Path $artDir "ipconfig_all.txt"
Write-TextFile -Path $sysinfoPath -Content (Invoke-ExeCapture -File "systeminfo.exe").StdOut
Write-TextFile -Path $ipconfigPath -Content (Invoke-ExeCapture -File "ipconfig.exe" -Args @("/all")).StdOut
$inventory.Artifacts.SystemInfo = $sysinfoPath
$inventory.Artifacts.IpconfigAll = $ipconfigPath

# Hash key output files
$inventory.FileHashes.Hosts = [pscustomobject]@{ 
  Path = "$env:SystemRoot\System32\drivers\etc\hosts"
  Sha256 = (Get-FileHashSafe "$env:SystemRoot\System32\drivers\etc\hosts") 
}

# Memory cleanup
[System.GC]::Collect()

# Finalize timing
$script:EndTime = Get-Date
$inventory.Metadata.ExecutionTime.End = $script:EndTime
$inventory.Metadata.ExecutionTime.DurationSeconds = 
  [math]::Round(($script:EndTime - $script:StartTime).TotalSeconds, 2)
$inventory.Metadata.ErrorCount = $script:ErrorLog.Count

# Save errors if any
if ($script:ErrorLog.Count -gt 0) {
  $errorCsv = Join-Path $csvDir "collection_errors.csv"
  Export-CsvSafe -Data $script:ErrorLog -Path $errorCsv
  $inventory.Artifacts.ErrorLog = $errorCsv
  Write-LogEntry "Encountered $($script:ErrorLog.Count) errors during collection" -Level "WARN"
}

# ---------------------------- Baseline Management ----------------------------

$baselineDir = Get-BaselineDirectory -CustomPath $BaselinePath
$baselineExists = Test-BaselineExists -BaselineDir $baselineDir
$baselineComparison = $null

if ($UpdateBaseline) {
  # Force update baseline
  Write-Host ""
  Write-Host "Updating baseline at: $baselineDir" -ForegroundColor Cyan
  $saved = Save-Baseline -BaselineDir $baselineDir -Inventory $inventory
  if ($saved) {
    Write-Host "Baseline updated successfully" -ForegroundColor Green
    Write-Host ""
  }
} elseif ($baselineExists -and -not $SkipComparison) {
  # Compare with existing baseline
  Write-Host ""
  Write-Host "Comparing with baseline at: $baselineDir" -ForegroundColor Cyan
  $baselineComparison = Compare-WithBaseline -BaselineDir $baselineDir -CurrentInventory $inventory -ComparisonCsvDir $csvDir

  if ($baselineComparison) {
    $inventory.BaselineComparison = $baselineComparison

    # Log comparison results
    if ($baselineComparison.TotalChanges -gt 0) {
      Write-LogEntry "Baseline comparison: $($baselineComparison.TotalChanges) changes detected since baseline" -Level "WARN"
    } else {
      Write-LogEntry "Baseline comparison: No changes detected" -Level "SUCCESS"
    }
  }
} elseif (-not $baselineExists -and -not $SkipComparison) {
  # No baseline exists - create one automatically
  Write-Host ""
  Write-Host "No baseline found - creating new baseline at: $baselineDir" -ForegroundColor Yellow
  $saved = Save-Baseline -BaselineDir $baselineDir -Inventory $inventory
  if ($saved) {
    Write-Host "Baseline created successfully" -ForegroundColor Green
    Write-Host "Future runs will compare against this baseline" -ForegroundColor Cyan
    Write-Host ""
  }
}

# Write JSON report
Write-LogEntry "Writing JSON summary"
$jsonPath = Join-Path $reportDir "inventory.json"
try {
  ($inventory | ConvertTo-Json -Depth 10) | Out-File -FilePath $jsonPath -Encoding UTF8 -Force
} catch {
  Write-LogEntry "Failed to write JSON: $_" -Level "ERROR"
}

# Create enhanced HTML report
Write-LogEntry "Writing HTML report"
$htmlPath = Join-Path $reportDir "system_report.html"

$sys = $inventory.System
$sec = $inventory.Security

$htmlStyle = @"
<style>
  body { 
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
    margin: 20px; 
    background-color: #f5f5f5; 
  }
  .header { 
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
    color: white; 
    padding: 30px; 
    border-radius: 10px; 
    margin-bottom: 20px; 
  }
  .header h1 { margin: 0; font-size: 2em; }
  .header p { margin: 5px 0; opacity: 0.9; }
  .section { 
    background: white; 
    padding: 20px; 
    margin-bottom: 20px; 
    border-radius: 10px; 
    box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
  }
  .section h2 { 
    color: #667eea; 
    border-bottom: 2px solid #667eea; 
    padding-bottom: 10px; 
    margin-top: 0; 
  }
  table { 
    border-collapse: collapse; 
    width: 100%; 
    margin-bottom: 20px; 
  }
  th { 
    background-color: #667eea; 
    color: white; 
    padding: 12px; 
    text-align: left; 
    font-weight: 600; 
  }
  td { 
    padding: 10px; 
    border-bottom: 1px solid #e0e0e0; 
  }
  tr:hover { background-color: #f8f9fa; }
  .metric { 
    display: inline-block; 
    background: #f8f9fa; 
    padding: 15px 20px; 
    margin: 10px 10px 10px 0; 
    border-radius: 8px; 
    border-left: 4px solid #667eea; 
  }
  .metric-label { 
    font-size: 0.85em; 
    color: #666; 
    text-transform: uppercase; 
  }
  .metric-value { 
    font-size: 1.5em; 
    font-weight: bold; 
    color: #333; 
  }
  .warning { background-color: #fff3cd; border-left-color: #ffc107; }
  .danger { background-color: #f8d7da; border-left-color: #dc3545; }
  .success { background-color: #d4edda; border-left-color: #28a745; }
  .info { background-color: #d1ecf1; border-left-color: #17a2b8; }
  a { color: #667eea; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .footer { 
    text-align: center; 
    padding: 20px; 
    color: #666; 
    font-size: 0.9em; 
  }
</style>
"@

$threatSummary = ""
$totalThreats = $inventory.ThreatAnalysis.SuspiciousProcesses.Count +
                $inventory.ThreatAnalysis.SuspiciousServices.Count +
                $inventory.ThreatAnalysis.SuspiciousTasks.Count +
                $inventory.ThreatAnalysis.SuspiciousConnections.Count +
                $inventory.ThreatAnalysis.UnauthorizedAdmins.Count

$criticalWeaknesses = 0
if ($inventory.ThreatAnalysis.SecurityWeaknesses.Count -gt 0) {
  $weaknessData = Import-Csv $inventory.ThreatAnalysis.SecurityWeaknesses.Csv -ErrorAction SilentlyContinue
  if ($weaknessData) {
    $criticalWeaknesses = @($weaknessData | Where-Object { $_.Risk -eq 'Critical' }).Count
  }
}

if ($totalThreats -gt 0 -or $criticalWeaknesses -gt 0) {
  $threatClass = if ($criticalWeaknesses -gt 0) { "danger" } elseif ($totalThreats -gt 5) { "warning" } else { "info" }

  $threatMetrics = ""
  if ($inventory.ThreatAnalysis.SuspiciousProcesses.Count -gt 0) {
    $threatMetrics += "<div class='metric danger'><div class='metric-label'>Suspicious Processes</div><div class='metric-value'>$($inventory.ThreatAnalysis.SuspiciousProcesses.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'><a href='csv/threat_suspicious_processes.csv' style='color: #721c24;'>View Details</a></div></div>"
  }
  if ($inventory.ThreatAnalysis.SuspiciousServices.Count -gt 0) {
    $threatMetrics += "<div class='metric danger'><div class='metric-label'>Suspicious Services</div><div class='metric-value'>$($inventory.ThreatAnalysis.SuspiciousServices.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'><a href='csv/threat_suspicious_services.csv' style='color: #721c24;'>View Details</a></div></div>"
  }
  if ($inventory.ThreatAnalysis.SuspiciousTasks.Count -gt 0) {
    $threatMetrics += "<div class='metric danger'><div class='metric-label'>Suspicious Scheduled Tasks</div><div class='metric-value'>$($inventory.ThreatAnalysis.SuspiciousTasks.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'><a href='csv/threat_suspicious_tasks.csv' style='color: #721c24;'>View Details</a></div></div>"
  }
  if ($inventory.ThreatAnalysis.SuspiciousConnections.Count -gt 0) {
    $threatMetrics += "<div class='metric danger'><div class='metric-label'>Suspicious Network Connections</div><div class='metric-value'>$($inventory.ThreatAnalysis.SuspiciousConnections.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'><a href='csv/threat_suspicious_connections.csv' style='color: #721c24;'>View Details</a></div></div>"
  }
  if ($inventory.ThreatAnalysis.UnauthorizedAdmins.Count -gt 0) {
    $threatMetrics += "<div class='metric danger'><div class='metric-label'>Unauthorized Admins</div><div class='metric-value'>$($inventory.ThreatAnalysis.UnauthorizedAdmins.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'><a href='csv/threat_unauthorized_admins.csv' style='color: #721c24;'>View Details</a></div></div>"
  }
  if ($criticalWeaknesses -gt 0) {
    $threatMetrics += "<div class='metric danger'><div class='metric-label'>Critical Security Issues</div><div class='metric-value'>$criticalWeaknesses</div><div style='font-size: 0.8em; margin-top: 5px;'><a href='csv/security_weaknesses.csv' style='color: #721c24;'>View Details</a></div></div>"
  }
  if ($inventory.ThreatAnalysis.RecentModifications.Count -gt 0) {
    $threatMetrics += "<div class='metric warning'><div class='metric-label'>Recent System File Changes (24h)</div><div class='metric-value'>$($inventory.ThreatAnalysis.RecentModifications.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'><a href='csv/recent_system_modifications_24h.csv' style='color: #856404;'>View Details</a></div></div>"
  }

  $threatSummary = "<div class='section $threatClass'><h2>[!] CCDC THREAT ANALYSIS - IMMEDIATE ATTENTION REQUIRED</h2><div style='font-size: 1.2em; margin: 15px 0;'><strong>Total Suspicious Items: $totalThreats</strong> | <strong>Critical Security Issues: $criticalWeaknesses</strong></div><div style='display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-top: 20px;'>$threatMetrics</div><div style='margin-top: 20px; padding: 15px; background: rgba(255,255,255,0.3); border-radius: 5px;'><strong>Next Steps:</strong><ol style='margin: 10px 0;'><li>Review all suspicious items in the CSV files linked above</li><li>Investigate processes, services, and tasks running from unusual locations</li><li>Verify all network connections, especially to uncommon ports</li><li>Check unauthorized administrators and remove if needed</li><li>Address critical security weaknesses immediately (Defender, Firewall, UAC)</li><li>Review recent system file modifications for unauthorized changes</li></ol></div></div>"
}

# Generate baseline comparison section
$baselineSection = ""
if ($baselineComparison) {
  $baselineDate = try { ([datetime]$baselineComparison.BaselineDate).ToString("yyyy-MM-dd HH:mm") } catch { "Unknown" }
  $totalChanges = $baselineComparison.TotalChanges

  $changeClass = if ($baselineComparison.Admins.Count -gt 0) { "danger" } elseif ($totalChanges -gt 10) { "warning" } elseif ($totalChanges -gt 0) { "info" } else { "success" }

  $changeMetrics = ""

  # Processes
  if ($baselineComparison.Processes.Count -gt 0) {
    $addedCount = $baselineComparison.Processes.Added.Count
    $removedCount = $baselineComparison.Processes.Removed.Count
    $csvLink = if ($baselineComparison.Processes.Csv) { $baselineComparison.Processes.Csv.Replace($reportDir + "\", "") } else { "" }
    $changeMetrics += "<div class='metric warning'><div class='metric-label'>Processes Changed</div><div class='metric-value'>$($baselineComparison.Processes.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'>+$addedCount / -$removedCount<br/><a href='$csvLink' style='color: #856404;'>View Details</a></div></div>"
  }

  # Services
  if ($baselineComparison.Services.Count -gt 0) {
    $addedCount = $baselineComparison.Services.Added.Count
    $removedCount = $baselineComparison.Services.Removed.Count
    $csvLink = if ($baselineComparison.Services.Csv) { $baselineComparison.Services.Csv.Replace($reportDir + "\", "") } else { "" }
    $changeMetrics += "<div class='metric warning'><div class='metric-label'>Services Changed</div><div class='metric-value'>$($baselineComparison.Services.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'>+$addedCount / -$removedCount<br/><a href='$csvLink' style='color: #856404;'>View Details</a></div></div>"
  }

  # Scheduled Tasks
  if ($baselineComparison.Tasks.Count -gt 0) {
    $addedCount = $baselineComparison.Tasks.Added.Count
    $removedCount = $baselineComparison.Tasks.Removed.Count
    $csvLink = if ($baselineComparison.Tasks.Csv) { $baselineComparison.Tasks.Csv.Replace($reportDir + "\", "") } else { "" }
    $changeMetrics += "<div class='metric warning'><div class='metric-label'>Tasks Changed</div><div class='metric-value'>$($baselineComparison.Tasks.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'>+$addedCount / -$removedCount<br/><a href='$csvLink' style='color: #856404;'>View Details</a></div></div>"
  }

  # Users
  if ($baselineComparison.Users.Count -gt 0) {
    $addedCount = $baselineComparison.Users.Added.Count
    $removedCount = $baselineComparison.Users.Removed.Count
    $csvLink = if ($baselineComparison.Users.Csv) { $baselineComparison.Users.Csv.Replace($reportDir + "\", "") } else { "" }
    $changeMetrics += "<div class='metric warning'><div class='metric-label'>Users Changed</div><div class='metric-value'>$($baselineComparison.Users.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'>+$addedCount / -$removedCount<br/><a href='$csvLink' style='color: #856404;'>View Details</a></div></div>"
  }

  # Administrators (HIGH PRIORITY)
  if ($baselineComparison.Admins.Count -gt 0) {
    $addedCount = $baselineComparison.Admins.Added.Count
    $removedCount = $baselineComparison.Admins.Removed.Count
    $csvLink = if ($baselineComparison.Admins.Csv) { $baselineComparison.Admins.Csv.Replace($reportDir + "\", "") } else { "" }
    $changeMetrics += "<div class='metric danger'><div class='metric-label'>ADMINS Changed</div><div class='metric-value'>$($baselineComparison.Admins.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'>+$addedCount / -$removedCount<br/><a href='$csvLink' style='color: #721c24;'>View Details</a></div></div>"
  }

  # Software
  if ($baselineComparison.Software.Count -gt 0) {
    $addedCount = $baselineComparison.Software.Added.Count
    $removedCount = $baselineComparison.Software.Removed.Count
    $csvLink = if ($baselineComparison.Software.Csv) { $baselineComparison.Software.Csv.Replace($reportDir + "\", "") } else { "" }
    $changeMetrics += "<div class='metric info'><div class='metric-label'>Software Changed</div><div class='metric-value'>$($baselineComparison.Software.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'>+$addedCount / -$removedCount<br/><a href='$csvLink' style='color: #0c5460;'>View Details</a></div></div>"
  }

  # Autoruns
  if ($baselineComparison.Autoruns.Count -gt 0) {
    $addedCount = $baselineComparison.Autoruns.Added.Count
    $removedCount = $baselineComparison.Autoruns.Removed.Count
    $csvLink = if ($baselineComparison.Autoruns.Csv) { $baselineComparison.Autoruns.Csv.Replace($reportDir + "\", "") } else { "" }
    $changeMetrics += "<div class='metric warning'><div class='metric-label'>Autoruns Changed</div><div class='metric-value'>$($baselineComparison.Autoruns.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'>+$addedCount / -$removedCount<br/><a href='$csvLink' style='color: #856404;'>View Details</a></div></div>"
  }

  # Shares
  if ($baselineComparison.Shares.Count -gt 0) {
    $addedCount = $baselineComparison.Shares.Added.Count
    $removedCount = $baselineComparison.Shares.Removed.Count
    $csvLink = if ($baselineComparison.Shares.Csv) { $baselineComparison.Shares.Csv.Replace($reportDir + "\", "") } else { "" }
    $changeMetrics += "<div class='metric warning'><div class='metric-label'>Shares Changed</div><div class='metric-value'>$($baselineComparison.Shares.Count)</div><div style='font-size: 0.8em; margin-top: 5px;'>+$addedCount / -$removedCount<br/><a href='$csvLink' style='color: #856404;'>View Details</a></div></div>"
  }

  $statusText = if ($totalChanges -eq 0) {
    "<div style='font-size: 1.2em; margin: 15px 0; color: #28a745;'><strong>[OK] No changes detected since baseline</strong></div>"
  } else {
    "<div style='font-size: 1.2em; margin: 15px 0;'><strong>Total Changes: $totalChanges</strong></div>"
  }

  # Generate detailed change tables
  $detailedChanges = ""

  # Helper function to create change table HTML
  function Get-ChangeTableHtml {
    param(
      [string]$CategoryName,
      [string]$CsvPath,
      [array]$AddedItems,
      [array]$RemovedItems,
      [string]$IconColor = "#856404"
    )

    if (-not $CsvPath -or -not (Test-Path $CsvPath)) {
      return ""
    }

    try {
      $changeData = Import-Csv $CsvPath
      if ($changeData.Count -eq 0) { return "" }

      $html = "<details style='margin: 20px 0; border: 1px solid #ddd; border-radius: 5px; padding: 10px; background: rgba(255,255,255,0.5);'>"
      $html += "<summary style='cursor: pointer; font-weight: bold; font-size: 1.1em; color: $IconColor; padding: 5px;'>&#9658; $CategoryName Changes ($($changeData.Count) total: +$($AddedItems.Count) / -$($RemovedItems.Count))</summary>"
      $html += "<div style='margin-top: 15px;'>"

      # Added items section
      if ($AddedItems.Count -gt 0) {
        $html += "<div style='margin-bottom: 20px;'>"
        $html += "<h4 style='color: #28a745; margin-bottom: 10px;'>&#10133; Added ($($AddedItems.Count))</h4>"
        $html += "<div style='overflow-x: auto;'><table style='width: 100%; border-collapse: collapse; font-size: 0.9em;'>"

        # Get column headers from first added item
        $addedData = $changeData | Where-Object { $_.Change -eq "ADDED" }
        if ($addedData.Count -gt 0) {
          $columns = ($addedData | Select-Object -First 1).PSObject.Properties.Name | Where-Object { $_ -ne "Change" }
          $html += "<thead><tr style='background: #d4edda; border-bottom: 2px solid #28a745;'>"
          foreach ($col in $columns) {
            $html += "<th style='padding: 8px; text-align: left; border: 1px solid #c3e6cb;'>$col</th>"
          }
          $html += "</tr></thead><tbody>"

          foreach ($row in $addedData) {
            $html += "<tr style='border-bottom: 1px solid #d4edda;'>"
            foreach ($col in $columns) {
              $value = $row.$col
              if ([string]::IsNullOrWhiteSpace($value)) { $value = "-" }
              $displayValue = if ($value.Length -gt 80) { $value.Substring(0, 77) + "..." } else { $value }
              $html += "<td style='padding: 6px 8px; border: 1px solid #d4edda;' title='$([System.Web.HttpUtility]::HtmlEncode($value))'>$([System.Web.HttpUtility]::HtmlEncode($displayValue))</td>"
            }
            $html += "</tr>"
          }
          $html += "</tbody>"
        }
        $html += "</table></div></div>"
      }

      # Removed items section
      if ($RemovedItems.Count -gt 0) {
        $html += "<div style='margin-bottom: 10px;'>"
        $html += "<h4 style='color: #dc3545; margin-bottom: 10px;'>&#10134; Removed ($($RemovedItems.Count))</h4>"
        $html += "<div style='overflow-x: auto;'><table style='width: 100%; border-collapse: collapse; font-size: 0.9em;'>"

        # Get column headers from first removed item
        $removedData = $changeData | Where-Object { $_.Change -eq "REMOVED" }
        if ($removedData.Count -gt 0) {
          $columns = ($removedData | Select-Object -First 1).PSObject.Properties.Name | Where-Object { $_ -ne "Change" }
          $html += "<thead><tr style='background: #f8d7da; border-bottom: 2px solid #dc3545;'>"
          foreach ($col in $columns) {
            $html += "<th style='padding: 8px; text-align: left; border: 1px solid #f5c6cb;'>$col</th>"
          }
          $html += "</tr></thead><tbody>"

          foreach ($row in $removedData) {
            $html += "<tr style='border-bottom: 1px solid #f8d7da;'>"
            foreach ($col in $columns) {
              $value = $row.$col
              if ([string]::IsNullOrWhiteSpace($value)) { $value = "-" }
              $displayValue = if ($value.Length -gt 80) { $value.Substring(0, 77) + "..." } else { $value }
              $html += "<td style='padding: 6px 8px; border: 1px solid #f8d7da;' title='$([System.Web.HttpUtility]::HtmlEncode($value))'>$([System.Web.HttpUtility]::HtmlEncode($displayValue))</td>"
            }
            $html += "</tr>"
          }
          $html += "</tbody>"
        }
        $html += "</table></div></div>"
      }

      $csvRelPath = $CsvPath.Replace($reportDir + "\", "")
      $html += "<div style='margin-top: 10px; text-align: right;'><a href='$csvRelPath' style='color: $IconColor; text-decoration: none;'>&#128190; Download Full CSV</a></div>"
      $html += "</div></details>"

      return $html
    } catch {
      return ""
    }
  }

  # Add System.Web assembly for HTML encoding
  Add-Type -AssemblyName System.Web

  # Generate detailed tables for each category
  if ($baselineComparison.Processes.Count -gt 0) {
    $detailedChanges += Get-ChangeTableHtml -CategoryName "Processes" -CsvPath $baselineComparison.Processes.Csv -AddedItems $baselineComparison.Processes.Added -RemovedItems $baselineComparison.Processes.Removed -IconColor "#856404"
  }

  if ($baselineComparison.Services.Count -gt 0) {
    $detailedChanges += Get-ChangeTableHtml -CategoryName "Services" -CsvPath $baselineComparison.Services.Csv -AddedItems $baselineComparison.Services.Added -RemovedItems $baselineComparison.Services.Removed -IconColor "#856404"
  }

  if ($baselineComparison.Tasks.Count -gt 0) {
    $detailedChanges += Get-ChangeTableHtml -CategoryName "Scheduled Tasks" -CsvPath $baselineComparison.Tasks.Csv -AddedItems $baselineComparison.Tasks.Added -RemovedItems $baselineComparison.Tasks.Removed -IconColor "#856404"
  }

  if ($baselineComparison.Users.Count -gt 0) {
    $detailedChanges += Get-ChangeTableHtml -CategoryName "Users" -CsvPath $baselineComparison.Users.Csv -AddedItems $baselineComparison.Users.Added -RemovedItems $baselineComparison.Users.Removed -IconColor "#856404"
  }

  if ($baselineComparison.Admins.Count -gt 0) {
    $detailedChanges += Get-ChangeTableHtml -CategoryName "ADMINISTRATORS" -CsvPath $baselineComparison.Admins.Csv -AddedItems $baselineComparison.Admins.Added -RemovedItems $baselineComparison.Admins.Removed -IconColor "#721c24"
  }

  if ($baselineComparison.Software.Count -gt 0) {
    $detailedChanges += Get-ChangeTableHtml -CategoryName "Software" -CsvPath $baselineComparison.Software.Csv -AddedItems $baselineComparison.Software.Added -RemovedItems $baselineComparison.Software.Removed -IconColor "#0c5460"
  }

  if ($baselineComparison.Autoruns.Count -gt 0) {
    $detailedChanges += Get-ChangeTableHtml -CategoryName "Autoruns" -CsvPath $baselineComparison.Autoruns.Csv -AddedItems $baselineComparison.Autoruns.Added -RemovedItems $baselineComparison.Autoruns.Removed -IconColor "#856404"
  }

  if ($baselineComparison.Shares.Count -gt 0) {
    $detailedChanges += Get-ChangeTableHtml -CategoryName "Network Shares" -CsvPath $baselineComparison.Shares.Csv -AddedItems $baselineComparison.Shares.Added -RemovedItems $baselineComparison.Shares.Removed -IconColor "#856404"
  }

  $baselineSection = "<div class='section $changeClass'><h2>BASELINE COMPARISON (since $baselineDate)</h2>$statusText<div style='display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px;'>$changeMetrics</div>$detailedChanges</div>"
}

# Ensure $sys and $sec are valid with default properties
if (-not $sys) {
  $sys = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Domain = $null
    PartOfDomain = $false
    Manufacturer = $null
    Model = $null
    OSName = $null
    OSVersion = $null
    OSBuildNumber = $null
    OSArchitecture = $null
    InstallDate = $null
    LastBootUpTime = $null
    UptimeHours = $null
    BIOSVersion = $null
    BIOSSerial = $null
    CPUName = $null
    CPUCores = $null
    CPULogicalProcessors = $null
    TotalMemoryGB = $null
    IsAdmin = $false
    TimeCollected = (Get-Date).ToString("o")
  }
}

if (-not $sec) {
  $sec = [pscustomobject]@{
    UAC = [pscustomobject]@{ EnableLUA = $null }
    RDP_DenyTSConnections = $null
  }
}

$adminClass = if ($sys.IsAdmin) { 'success' } else { 'warning' }
$adminText = if ($sys.IsAdmin) { 'YES' } else { 'NO' }
$summaryMetrics = "<div class='metric $adminClass'><div class='metric-label'>Admin Rights</div><div class='metric-value'>$adminText</div></div>"
$summaryMetrics += "<div class='metric'><div class='metric-label'>Services</div><div class='metric-value'>$($inventory.Services.Count)</div></div>"
$summaryMetrics += "<div class='metric'><div class='metric-label'>Processes</div><div class='metric-value'>$($inventory.Processes.Count)</div></div>"
$summaryMetrics += "<div class='metric'><div class='metric-label'>Scheduled Tasks</div><div class='metric-value'>$($inventory.Tasks.Count)</div></div>"
$summaryMetrics += "<div class='metric'><div class='metric-label'>Autoruns</div><div class='metric-value'>$($inventory.Autoruns.Count)</div></div>"
$summaryMetrics += "<div class='metric'><div class='metric-label'>Software</div><div class='metric-value'>$($inventory.Software.Count)</div></div>"
$summaryMetrics += "<div class='metric'><div class='metric-label'>Patches</div><div class='metric-value'>$($inventory.Patches.Count)</div></div>"
$summaryMetrics += "<div class='metric'><div class='metric-label'>Established Connections</div><div class='metric-value'>$($inventory.EstablishedConnections.Count)</div></div>"

$summaryTable = @(
  [pscustomobject]@{ Category="System"; Key="Computer Name"; Value=($sys.ComputerName) },
  [pscustomobject]@{ Category="System"; Key="Domain"; Value=($sys.Domain) },
  [pscustomobject]@{ Category="System"; Key="Part of Domain"; Value=($sys.PartOfDomain) },
  [pscustomobject]@{ Category="System"; Key="Operating System"; Value=("$($sys.OSName) ($($sys.OSArchitecture))") },
  [pscustomobject]@{ Category="System"; Key="OS Version/Build"; Value=("$($sys.OSVersion) / $($sys.OSBuildNumber)") },
  [pscustomobject]@{ Category="System"; Key="Last Boot"; Value=($sys.LastBootUpTime) },
  [pscustomobject]@{ Category="System"; Key="Uptime (Hours)"; Value=($sys.UptimeHours) },
  [pscustomobject]@{ Category="Hardware"; Key="Manufacturer/Model"; Value=("$($sys.Manufacturer) / $($sys.Model)") },
  [pscustomobject]@{ Category="Hardware"; Key="CPU"; Value=($sys.CPUName) },
  [pscustomobject]@{ Category="Hardware"; Key="CPU Cores"; Value=($sys.CPUCores) },
  [pscustomobject]@{ Category="Hardware"; Key="RAM (GB)"; Value=($sys.TotalMemoryGB) },
  [pscustomobject]@{ Category="Security"; Key="UAC Enabled"; Value=($sec.UAC.EnableLUA) },
  [pscustomobject]@{ Category="Security"; Key="RDP Denied"; Value=($sec.RDP_DenyTSConnections) },
  [pscustomobject]@{ Category="Network"; Key="TCP Connections"; Value=($inventory.Ports.TcpCount) },
  [pscustomobject]@{ Category="Network"; Key="UDP Endpoints"; Value=($inventory.Ports.UdpCount) },
  [pscustomobject]@{ Category="Inventory"; Key="Network Shares"; Value=($inventory.Shares.Count) },
  [pscustomobject]@{ Category="Inventory"; Key="Certificates"; Value=($inventory.Certs.Count) }
)

$summaryHtml = $summaryTable | ConvertTo-Html -Property Category, Key, Value -Fragment

$artifactLinks = "<ul>"
foreach ($k in $inventory.Artifacts.Keys) {
  $v = $inventory.Artifacts[$k]
  $relPath = $v.Replace($reportDir + "\", "")
  $artifactLinks += "<li><b>$k</b>: <a href='$relPath'>$relPath</a></li>"
}
$artifactLinks += "</ul>"

$errorSection = ""
if ($inventory.Metadata.ErrorCount -gt 0) {
  $errorSection = "<div class='section danger'><h2>[!] Collection Errors ($($inventory.Metadata.ErrorCount))</h2><p>Some data collection operations encountered errors. See <a href='csv/collection_errors.csv'>collection_errors.csv</a> for details.</p></div>"
}

$htmlContent = "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Windows Inventory Report - $($sys.ComputerName)</title>$htmlStyle</head><body>"
$htmlContent += "<div class='header'><h1>Windows Inventory Report - CCDC Edition</h1>"
$htmlContent += "<p><b>Computer:</b> $($sys.ComputerName) | <b>Collected:</b> $($inventory.Metadata.CollectedAt)</p>"
$htmlContent += "<p><b>Duration:</b> $($inventory.Metadata.ExecutionTime.DurationSeconds)s | <b>Quick Mode:</b> $($inventory.Metadata.QuickMode)</p></div>"
$htmlContent += $errorSection
$htmlContent += $baselineSection
$htmlContent += $threatSummary
$htmlContent += "<div class='section'><h2>Summary Metrics</h2>$summaryMetrics</div>"
$htmlContent += "<div class='section'><h2>System Details</h2>$summaryHtml</div>"
$htmlContent += "<div class='section'><h2>Artifacts &amp; Reports</h2>"
$htmlContent += "<p><b>JSON Summary:</b> <a href='inventory.json'>inventory.json</a></p>"
$htmlContent += "<p><b>Collection Log:</b> <a href='collection.log'>collection.log</a></p>"
$htmlContent += $artifactLinks
$htmlContent += "</div>"
$htmlContent += "<div class='footer'><p>Generated by Get-WindowsInventory.ps1 v2.1 (CCDC Enhanced Edition)</p>"
$htmlContent += "<p>Report Directory: $reportDir</p>"
$htmlContent += "<p style='margin-top: 10px; font-size: 0.9em;'><strong>CCDC Features:</strong> Automated threat detection, suspicious activity flagging, security weakness identification, and actionable recommendations for defenders.</p>"
$htmlContent += "</div></body></html>"

try {
  $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -Force
} catch {
  Write-LogEntry "Failed to write HTML report: $_" -Level "ERROR"
}

# Final file hashes
$inventory.FileHashes.InventoryJson = [pscustomobject]@{ 
  Path = $jsonPath
  Sha256 = (Get-FileHashSafe $jsonPath) 
}
$inventory.FileHashes.HtmlReport = [pscustomobject]@{ 
  Path = $htmlPath
  Sha256 = (Get-FileHashSafe $htmlPath) 
}

# Overwrite JSON with final hashes
try {
  ($inventory | ConvertTo-Json -Depth 10) | Out-File -FilePath $jsonPath -Encoding UTF8 -Force
} catch {}

# Compression (optional)
$zipPath = $null
if ($Compress) {
  $zipPath = Compress-ReportFolder -FolderPath $reportDir
}

# Complete progress
Write-ProgressSafe -Activity "Windows Inventory Collection" -Status "Complete" -PercentComplete 100
Write-Progress -Activity "Windows Inventory Collection" -Completed

# Final summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Collection Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-LogEntry "Collection complete" -Level "SUCCESS"
Write-LogEntry "Report folder: $reportDir"
Write-LogEntry "JSON summary: $jsonPath"
Write-LogEntry "HTML report: $htmlPath"

if ($zipPath) {
  Write-LogEntry "Compressed archive: $zipPath"
}

Write-Host "Report folder:  " -NoNewline
Write-Host $reportDir -ForegroundColor Cyan
Write-Host "JSON summary:   " -NoNewline
Write-Host $jsonPath -ForegroundColor Cyan
Write-Host "HTML report:    " -NoNewline
Write-Host $htmlPath -ForegroundColor Cyan

if ($zipPath) {
  Write-Host "ZIP archive:    " -NoNewline
  Write-Host $zipPath -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Execution time: $($inventory.Metadata.ExecutionTime.DurationSeconds)s" -ForegroundColor Yellow

if ($inventory.Metadata.ErrorCount -gt 0) {
  Write-Host "Errors encountered: $($inventory.Metadata.ErrorCount) (see collection.log)" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CCDC THREAT ANALYSIS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$totalThreatsConsole = $inventory.ThreatAnalysis.SuspiciousProcesses.Count +
                       $inventory.ThreatAnalysis.SuspiciousServices.Count +
                       $inventory.ThreatAnalysis.SuspiciousTasks.Count +
                       $inventory.ThreatAnalysis.SuspiciousConnections.Count +
                       $inventory.ThreatAnalysis.UnauthorizedAdmins.Count

if ($totalThreatsConsole -gt 0) {
  Write-Host ""
  Write-Host "[!] THREATS DETECTED: $totalThreatsConsole suspicious items found" -ForegroundColor Red
  Write-Host ""

  if ($inventory.ThreatAnalysis.SuspiciousProcesses.Count -gt 0) {
    Write-Host "  [!] Suspicious Processes: $($inventory.ThreatAnalysis.SuspiciousProcesses.Count)" -ForegroundColor Yellow
  }
  if ($inventory.ThreatAnalysis.SuspiciousServices.Count -gt 0) {
    Write-Host "  [!] Suspicious Services: $($inventory.ThreatAnalysis.SuspiciousServices.Count)" -ForegroundColor Yellow
  }
  if ($inventory.ThreatAnalysis.SuspiciousTasks.Count -gt 0) {
    Write-Host "  [!] Suspicious Scheduled Tasks: $($inventory.ThreatAnalysis.SuspiciousTasks.Count)" -ForegroundColor Yellow
  }
  if ($inventory.ThreatAnalysis.SuspiciousConnections.Count -gt 0) {
    Write-Host "  [!] Suspicious Network Connections: $($inventory.ThreatAnalysis.SuspiciousConnections.Count)" -ForegroundColor Yellow
  }
  if ($inventory.ThreatAnalysis.UnauthorizedAdmins.Count -gt 0) {
    Write-Host "  [!] Potentially Unauthorized Admins: $($inventory.ThreatAnalysis.UnauthorizedAdmins.Count)" -ForegroundColor Yellow
  }
} else {
  Write-Host ""
  Write-Host "[OK] No immediate threats detected" -ForegroundColor Green
}

if ($inventory.ThreatAnalysis.SecurityWeaknesses.Count -gt 0) {
  Write-Host ""
  Write-Host "[!] SECURITY WEAKNESSES: $($inventory.ThreatAnalysis.SecurityWeaknesses.Count) configuration issues found" -ForegroundColor Yellow

  # Show critical weaknesses
  if (Test-Path $inventory.ThreatAnalysis.SecurityWeaknesses.Csv) {
    $weaknessData = Import-Csv $inventory.ThreatAnalysis.SecurityWeaknesses.Csv
    $criticalIssues = $weaknessData | Where-Object { $_.Risk -eq 'Critical' }
    if ($criticalIssues) {
      Write-Host ""
      Write-Host "  CRITICAL ISSUES:" -ForegroundColor Red
      foreach ($issue in $criticalIssues) {
        Write-Host "    * $($issue.Issue)" -ForegroundColor Red
        Write-Host "      > $($issue.Recommendation)" -ForegroundColor White
      }
    }
  }
}

if ($inventory.ThreatAnalysis.RecentModifications.Count -gt 0) {
  Write-Host ""
  Write-Host "[i] $($inventory.ThreatAnalysis.RecentModifications.Count) recent system file modifications (last 24h)" -ForegroundColor Cyan
}

# Baseline comparison summary
if ($baselineComparison) {
  Write-Host ""
  Write-Host "========================================" -ForegroundColor Cyan
  Write-Host "  BASELINE COMPARISON" -ForegroundColor Cyan
  Write-Host "========================================" -ForegroundColor Cyan
  Write-Host ""

  if ($baselineComparison.TotalChanges -eq 0) {
    Write-Host "[OK] No changes detected since baseline" -ForegroundColor Green
  } else {
    Write-Host "[!] CHANGES DETECTED: $($baselineComparison.TotalChanges) total changes since baseline" -ForegroundColor Yellow
    Write-Host ""

    if ($baselineComparison.Admins.Count -gt 0) {
      Write-Host "  [!] Administrators Changed: $($baselineComparison.Admins.Count)" -ForegroundColor Red
      if ($baselineComparison.Admins.Added.Count -gt 0) {
        Write-Host "      Added: $($baselineComparison.Admins.Added -join ', ')" -ForegroundColor Red
      }
      if ($baselineComparison.Admins.Removed.Count -gt 0) {
        Write-Host "      Removed: $($baselineComparison.Admins.Removed -join ', ')" -ForegroundColor Yellow
      }
    }

    if ($baselineComparison.Processes.Count -gt 0) {
      Write-Host "  [i] Processes Changed: $($baselineComparison.Processes.Count) (+$($baselineComparison.Processes.Added.Count) / -$($baselineComparison.Processes.Removed.Count))" -ForegroundColor Yellow
      if ($baselineComparison.Processes.Added.Count -gt 0) {
        $topItems = $baselineComparison.Processes.Added | Select-Object -First 5
        foreach ($item in $topItems) { Write-Host "      + $item" -ForegroundColor Green }
        if ($baselineComparison.Processes.Added.Count -gt 5) {
          Write-Host "      ... and $($baselineComparison.Processes.Added.Count - 5) more" -ForegroundColor DarkGray
        }
      }
      if ($baselineComparison.Processes.Removed.Count -gt 0) {
        $topItems = $baselineComparison.Processes.Removed | Select-Object -First 3
        foreach ($item in $topItems) { Write-Host "      - $item" -ForegroundColor Red }
        if ($baselineComparison.Processes.Removed.Count -gt 3) {
          Write-Host "      ... and $($baselineComparison.Processes.Removed.Count - 3) more" -ForegroundColor DarkGray
        }
      }
      Write-Host "      See: $($baselineComparison.Processes.Csv)" -ForegroundColor Cyan
    }

    if ($baselineComparison.Services.Count -gt 0) {
      Write-Host "  [i] Services Changed: $($baselineComparison.Services.Count) (+$($baselineComparison.Services.Added.Count) / -$($baselineComparison.Services.Removed.Count))" -ForegroundColor Yellow
      if ($baselineComparison.Services.Added.Count -gt 0) {
        $topItems = $baselineComparison.Services.Added | Select-Object -First 5
        foreach ($item in $topItems) { Write-Host "      + $item" -ForegroundColor Green }
        if ($baselineComparison.Services.Added.Count -gt 5) {
          Write-Host "      ... and $($baselineComparison.Services.Added.Count - 5) more" -ForegroundColor DarkGray
        }
      }
      if ($baselineComparison.Services.Removed.Count -gt 0) {
        $topItems = $baselineComparison.Services.Removed | Select-Object -First 3
        foreach ($item in $topItems) { Write-Host "      - $item" -ForegroundColor Red }
        if ($baselineComparison.Services.Removed.Count -gt 3) {
          Write-Host "      ... and $($baselineComparison.Services.Removed.Count - 3) more" -ForegroundColor DarkGray
        }
      }
      Write-Host "      See: $($baselineComparison.Services.Csv)" -ForegroundColor Cyan
    }

    if ($baselineComparison.Tasks.Count -gt 0) {
      Write-Host "  [i] Tasks Changed: $($baselineComparison.Tasks.Count) (+$($baselineComparison.Tasks.Added.Count) / -$($baselineComparison.Tasks.Removed.Count))" -ForegroundColor Yellow
      if ($baselineComparison.Tasks.Added.Count -gt 0) {
        $topItems = $baselineComparison.Tasks.Added | Select-Object -First 5
        foreach ($item in $topItems) { Write-Host "      + $item" -ForegroundColor Green }
        if ($baselineComparison.Tasks.Added.Count -gt 5) {
          Write-Host "      ... and $($baselineComparison.Tasks.Added.Count - 5) more" -ForegroundColor DarkGray
        }
      }
      if ($baselineComparison.Tasks.Removed.Count -gt 0) {
        $topItems = $baselineComparison.Tasks.Removed | Select-Object -First 3
        foreach ($item in $topItems) { Write-Host "      - $item" -ForegroundColor Red }
        if ($baselineComparison.Tasks.Removed.Count -gt 3) {
          Write-Host "      ... and $($baselineComparison.Tasks.Removed.Count - 3) more" -ForegroundColor DarkGray
        }
      }
      Write-Host "      See: $($baselineComparison.Tasks.Csv)" -ForegroundColor Cyan
    }

    if ($baselineComparison.Users.Count -gt 0) {
      Write-Host "  [i] Users Changed: $($baselineComparison.Users.Count) (+$($baselineComparison.Users.Added.Count) / -$($baselineComparison.Users.Removed.Count))" -ForegroundColor Yellow
      if ($baselineComparison.Users.Added.Count -gt 0) {
        foreach ($item in $baselineComparison.Users.Added) { Write-Host "      + $item" -ForegroundColor Green }
      }
      if ($baselineComparison.Users.Removed.Count -gt 0) {
        foreach ($item in $baselineComparison.Users.Removed) { Write-Host "      - $item" -ForegroundColor Red }
      }
      Write-Host "      See: $($baselineComparison.Users.Csv)" -ForegroundColor Cyan
    }

    if ($baselineComparison.Autoruns.Count -gt 0) {
      Write-Host "  [i] Autoruns Changed: $($baselineComparison.Autoruns.Count) (+$($baselineComparison.Autoruns.Added.Count) / -$($baselineComparison.Autoruns.Removed.Count))" -ForegroundColor Yellow
      if ($baselineComparison.Autoruns.Added.Count -gt 0) {
        $topItems = $baselineComparison.Autoruns.Added | Select-Object -First 5
        foreach ($item in $topItems) { Write-Host "      + $item" -ForegroundColor Green }
        if ($baselineComparison.Autoruns.Added.Count -gt 5) {
          Write-Host "      ... and $($baselineComparison.Autoruns.Added.Count - 5) more" -ForegroundColor DarkGray
        }
      }
      if ($baselineComparison.Autoruns.Removed.Count -gt 0) {
        $topItems = $baselineComparison.Autoruns.Removed | Select-Object -First 3
        foreach ($item in $topItems) { Write-Host "      - $item" -ForegroundColor Red }
        if ($baselineComparison.Autoruns.Removed.Count -gt 3) {
          Write-Host "      ... and $($baselineComparison.Autoruns.Removed.Count - 3) more" -ForegroundColor DarkGray
        }
      }
      Write-Host "      See: $($baselineComparison.Autoruns.Csv)" -ForegroundColor Cyan
    }

    if ($baselineComparison.Shares.Count -gt 0) {
      Write-Host "  [i] Shares Changed: $($baselineComparison.Shares.Count) (+$($baselineComparison.Shares.Added.Count) / -$($baselineComparison.Shares.Removed.Count))" -ForegroundColor Yellow
      if ($baselineComparison.Shares.Added.Count -gt 0) {
        foreach ($item in $baselineComparison.Shares.Added) { Write-Host "      + $item" -ForegroundColor Green }
      }
      if ($baselineComparison.Shares.Removed.Count -gt 0) {
        foreach ($item in $baselineComparison.Shares.Removed) { Write-Host "      - $item" -ForegroundColor Red }
      }
      Write-Host "      See: $($baselineComparison.Shares.Csv)" -ForegroundColor Cyan
    }

    if ($baselineComparison.Software.Count -gt 0) {
      Write-Host "  [i] Software Changed: $($baselineComparison.Software.Count) (+$($baselineComparison.Software.Added.Count) / -$($baselineComparison.Software.Removed.Count))" -ForegroundColor Cyan
      if ($baselineComparison.Software.Added.Count -gt 0) {
        $topItems = $baselineComparison.Software.Added | Select-Object -First 5
        foreach ($item in $topItems) { Write-Host "      + $item" -ForegroundColor Green }
        if ($baselineComparison.Software.Added.Count -gt 5) {
          Write-Host "      ... and $($baselineComparison.Software.Added.Count - 5) more" -ForegroundColor DarkGray
        }
      }
      if ($baselineComparison.Software.Removed.Count -gt 0) {
        $topItems = $baselineComparison.Software.Removed | Select-Object -First 3
        foreach ($item in $topItems) { Write-Host "      - $item" -ForegroundColor Red }
        if ($baselineComparison.Software.Removed.Count -gt 3) {
          Write-Host "      ... and $($baselineComparison.Software.Removed.Count - 3) more" -ForegroundColor DarkGray
        }
      }
      Write-Host "      See: $($baselineComparison.Software.Csv)" -ForegroundColor Cyan
    }
  }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Review the HTML report for detailed threat analysis:" -ForegroundColor White
Write-Host "   $htmlPath" -ForegroundColor Cyan
Write-Host ""
