<#
.SYNOPSIS
  List non-default Scheduled Tasks (anything NOT under \Microsoft\Windows\).

.DESCRIPTION
  Enumerates scheduled tasks, filters out \Microsoft\Windows\*, and outputs a detailed table.
  Also exports to CSV for evidence/IR notes.

.USAGE
  # Run in elevated PowerShell for best visibility
  .\List-NonDefaultScheduledTasks.ps1
  .\List-NonDefaultScheduledTasks.ps1 -OutCsv "C:\Users\Public\non_default_tasks.csv"
  .\List-NonDefaultScheduledTasks.ps1 -IncludeMicrosoftNonWindows  # include \Microsoft\Office\ etc., still excludes \Microsoft\Windows\
#>

[CmdletBinding()]
param(
  [string]$OutCsv = "$env:PUBLIC\non_default_scheduled_tasks.csv",
  [switch]$NoExport,
  [switch]$IncludeMicrosoftNonWindows
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Format-Actions {
  param($Actions)
  if (-not $Actions) { return "" }
  ($Actions | ForEach-Object {
      $exe = $_.Execute
      $arg = $_.Arguments
      if ($exe -and $arg) { "$exe $arg" }
      elseif ($exe) { "$exe" }
      else { $_.ToString() }
    }) -join " | "
}

function Get-PropSafe {
  param($Obj, [string]$Name)
  try {
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -ne $p) { return $p.Value }
    return $null
  } catch { return $null }
}

function Format-Triggers {
  param($Triggers)
  if (-not $Triggers) { return "" }

  ($Triggers | ForEach-Object {
      $t = $_
      $type = $t.GetType().Name

      $start = Get-PropSafe $t "StartBoundary"
      $end   = Get-PropSafe $t "EndBoundary"

      $rep = Get-PropSafe $t "Repetition"
      $interval = Get-PropSafe $rep "Interval"
      $duration = Get-PropSafe $rep "Duration"

      $parts = @($type)

      if ($start) { $parts += "Start=$start" }
      if ($end)   { $parts += "End=$end" }
      if ($interval) { $parts += "Every=$interval" }
      if ($duration) { $parts += "For=$duration" }

      $parts -join ", "
    }) -join " | "
}

# Ensure ScheduledTasks module is available
try {
  if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    Import-Module ScheduledTasks -ErrorAction Stop
  }
} catch {
  Write-Error "Get-ScheduledTask not available. Are you on a Windows edition with ScheduledTasks module? Error: $($_.Exception.Message)"
  exit 1
}

# Pull tasks
$allTasks = Get-ScheduledTask -ErrorAction Stop

# Filter out \Microsoft\Windows\*
$filtered = $allTasks | Where-Object { $_.TaskPath -notlike "\Microsoft\Windows\*" }

# Optional: exclude all \Microsoft\* (not just \Microsoft\Windows\)
if (-not $IncludeMicrosoftNonWindows) {
  # If you consider all Microsoft vendor tasks "default-ish", enable this filter:
  # (By default we keep \Microsoft\Office\, etc. because many environments legitimately use them.)
  # Comment out next line if you want to keep all non-Windows Microsoft tasks without -IncludeMicrosoftNonWindows.
  $filtered = $filtered | Where-Object { $_.TaskPath -notlike "\Microsoft\*" }
}

$results = foreach ($t in $filtered) {
  $info = $null
  try {
    $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
  } catch {
    # Some tasks may fail to read info due to permissions or transient issues; continue.
    $info = $null
  }

  [pscustomobject]@{
    TaskPath        = $t.TaskPath
    TaskName        = $t.TaskName
    State           = $t.State
    Author          = $t.Author
    Description     = $t.Description
    RunAs           = $t.Principal.UserId
    LogonType       = $t.Principal.LogonType
    RunLevel        = $t.Principal.RunLevel
    Actions         = Format-Actions $t.Actions
    Triggers        = Format-Triggers $t.Triggers
    LastRunTime     = if ($info) { $info.LastRunTime } else { $null }
    NextRunTime     = if ($info) { $info.NextRunTime } else { $null }
    LastTaskResult  = if ($info) { $info.LastTaskResult } else { $null }
    NumberOfMissedRuns = if ($info) { $info.NumberOfMissedRuns } else { $null }
  }
}

# Console output (triage-friendly)
Write-Host ""
Write-Host "Non-default Scheduled Tasks (excluding \Microsoft\Windows\*): $($results.Count)" -ForegroundColor Cyan
Write-Host "Host: $env:COMPUTERNAME  User: $env:USERNAME  Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host ""

$results |
  Sort-Object TaskPath, TaskName |
  Format-Table -AutoSize `
    TaskPath, TaskName, State, RunAs, LastRunTime, NextRunTime, Actions

# Export
if (-not $NoExport) {
  try {
    $results | Sort-Object TaskPath, TaskName | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutCsv
    Write-Host ""
    Write-Host "Exported CSV: $OutCsv" -ForegroundColor Green
  } catch {
    Write-Warning "Failed to export CSV to '$OutCsv': $($_.Exception.Message)"
  }
}

# Exit code useful for automation
exit 0
