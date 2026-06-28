<#
.SYNOPSIS
  CCDC/IR: Snapshot + De-privilege AD privileged groups + detect re-add sources + event review + rollback.

.DESCRIPTION
  - Exports snapshots (direct + recursive members) for Domain Admins / Enterprise Admins / Schema Admins (and optionally Administrators).
  - Removes all DIRECT members not in an allowlist (users/groups), with dry-run support.
  - Searches SYSVOL for GPP Groups.xml references.
  - Optionally generates a GPO XML report (if GroupPolicy module exists) and greps for relevant strings.
  - Queries DC Security log for group membership change events.
  - Supports rollback from a snapshot folder created by this script.

.NOTES
  Run as an account with permission to read/modify group membership (typically DA).
  Use -WhatIf first. In competition, always keep a break-glass path.
#>

[CmdletBinding(DefaultParameterSetName="Apply")]
param(
  # Actions
  [Parameter(ParameterSetName="Apply")]
  [switch]$Apply,

  [Parameter(ParameterSetName="Apply")]
  [switch]$WhatIf,

  [Parameter(ParameterSetName="Rollback", Mandatory=$true)]
  [string]$RollbackFrom,

  # Group targets
  [string[]]$Groups = @("Domain Admins","Enterprise Admins","Schema Admins"),

  [switch]$IncludeAdministratorsGroup,

  # Allowlist (SamAccountName)
  [string[]]$AllowUsers = @("Administrator", $env:USERNAME),

  # Output
  [string]$OutputRoot = "C:\Temp",

  # Extra checks
  [switch]$SearchSysvolGPP = $true,
  [switch]$ReportGPOs = $true,
  [switch]$QueryGroupChangeEvents = $true,

  # Event query tuning
  [int]$EventMax = 200,
  [int]$EventHoursBack = 12
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[*] $msg" }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err ($msg) { Write-Host "[X] $msg" -ForegroundColor Red }

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Not running elevated. Re-run PowerShell as Administrator."
  }
}

function Import-Modules {
  if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "ActiveDirectory module not found. Install RSAT AD tools or run on a Domain Controller."
  }
  Import-Module ActiveDirectory -ErrorAction Stop

  if ($ReportGPOs -and (Get-Module -ListAvailable -Name GroupPolicy)) {
    Import-Module GroupPolicy -ErrorAction Stop
  } elseif ($ReportGPOs) {
    Write-Warn "GroupPolicy module not found; skipping GPO report."
    $script:ReportGPOs = $false
  }
}

function Get-DomainInfo {
  $d = Get-ADDomain
  return @{
    DNSRoot = $d.DNSRoot
    NetBIOS = $d.NetBIOSName
    DN      = $d.DistinguishedName
  }
}

function Resolve-TargetGroups {
  $tg = @()
  $tg += $Groups
  if ($IncludeAdministratorsGroup) { $tg += "Administrators" }
  # De-dupe
  $tg | Select-Object -Unique
}

function Ensure-Folder($path) {
  if (-not (Test-Path $path)) { New-Item -ItemType Directory -Force -Path $path | Out-Null }
}

function Export-GroupSnapshot {
  param(
    [Parameter(Mandatory=$true)][string]$GroupName,
    [Parameter(Mandatory=$true)][string]$Folder
  )

  $grp = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
  if (-not $grp) {
    Write-Warn "Group not found (skipping snapshot): $GroupName"
    return $null
  }

  $direct = Get-ADGroupMember -Identity $GroupName -ErrorAction Stop
  $recur  = Get-ADGroupMember -Identity $GroupName -Recursive -ErrorAction Stop

  $directObj = $direct | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName
  $recurObj  = $recur  | Select-Object Name, SamAccountName, ObjectClass, DistinguishedName

  $safe = ($GroupName -replace '[^A-Za-z0-9_\- ]','') -replace ' ','_'
  $directCsv = Join-Path $Folder "$safe`_direct.csv"
  $recurCsv  = Join-Path $Folder "$safe`_recursive.csv"
  $directJson= Join-Path $Folder "$safe`_direct.json"

  $directObj | Export-Csv -NoTypeInformation -Path $directCsv
  $recurObj  | Export-Csv -NoTypeInformation -Path $recurCsv

  # JSON used for rollback (direct members only)
  $directObj | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 $directJson

  return @{
    GroupName  = $GroupName
    DirectCsv  = $directCsv
    RecurCsv   = $recurCsv
    DirectJson = $directJson
    Direct     = $directObj
  }
}

function Build-RemovalPlan {
  param(
    [Parameter(Mandatory=$true)]$DirectMembers,
    [Parameter(Mandatory=$true)][string[]]$AllowSam
  )

  # Remove anything not allowlisted (users OR groups). This is intentional for nested groups in DA.
  $toRemove = @()
  foreach ($m in $DirectMembers) {
    $sam = $m.SamAccountName
    if ([string]::IsNullOrWhiteSpace($sam)) {
      # Some objects may not have SamAccountName; keep conservative: do not remove automatically
      continue
    }
    if ($AllowSam -contains $sam) { continue }
    $toRemove += $m
  }
  return $toRemove
}

function Apply-RemovalPlan {
  param(
    [Parameter(Mandatory=$true)][string]$GroupName,
    [Parameter(Mandatory=$true)]$ToRemove,
    [switch]$WhatIfMode
  )

  if (-not $ToRemove -or $ToRemove.Count -eq 0) {
    Write-Info "No removals needed for: $GroupName"
    return
  }

  Write-Info "Removing $($ToRemove.Count) direct member(s) from '$GroupName'..."
  foreach ($m in $ToRemove) {
    $label = "$($m.ObjectClass):$($m.SamAccountName)"
    if ($WhatIfMode) {
      Write-Host "  WOULD REMOVE $label"
      Remove-ADGroupMember -Identity $GroupName -Members $m.DistinguishedName -Confirm:$false -WhatIf
    } else {
      Write-Host "  REMOVE      $label"
      Remove-ADGroupMember -Identity $GroupName -Members $m.DistinguishedName -Confirm:$false
    }
  }
}

function Verify-Group {
  param([Parameter(Mandatory=$true)][string]$GroupName)
  $grp = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
  if (-not $grp) { return }
  $direct = Get-ADGroupMember -Identity $GroupName -ErrorAction Stop |
    Select-Object Name, SamAccountName, ObjectClass
  Write-Info "Direct members now in '$GroupName':"
  $direct | Sort-Object ObjectClass, SamAccountName | Format-Table -AutoSize
}

function Search-SysvolGPP {
  param(
    [Parameter(Mandatory=$true)][string]$DomainDNS,
    [Parameter(Mandatory=$true)][string[]]$GroupNames,
    [Parameter(Mandatory=$true)][string]$Folder
  )
  $sysvol = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies"
  Write-Info "Searching SYSVOL GPP for Groups.xml references under: $sysvol"

  $hits = @()
  try {
    $files = Get-ChildItem -Path $sysvol -Recurse -Filter "Groups.xml" -ErrorAction Stop
    foreach ($f in $files) {
      $found = $false
      foreach ($g in $GroupNames) {
        if (Select-String -Path $f.FullName -Pattern [regex]::Escape($g) -Quiet) { $found = $true; break }
      }
      if ($found) { $hits += $f.FullName }
    }
  } catch {
    Write-Warn "SYSVOL search failed: $($_.Exception.Message)"
  }

  $out = Join-Path $Folder "SYSVOL_GPP_GroupsXml_hits.txt"
  $hits | Sort-Object -Unique | Out-File -Encoding UTF8 $out

  if ($hits.Count -gt 0) {
    Write-Warn "Potential re-add sources found (Groups.xml). Review: $out"
  } else {
    Write-Info "No Groups.xml hits for target group names."
  }
}

function Report-GPOs {
  param(
    [Parameter(Mandatory=$true)][string]$Folder
  )

  if (-not $script:ReportGPOs) { return }

  $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
  $xml = Join-Path $Folder "GPOReport_$stamp.xml"
  Write-Info "Generating full GPO XML report: $xml"
  Get-GPOReport -All -ReportType Xml -Path $xml

  $patterns = @(
    "RestrictedGroups",
    "GroupMembership",
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators"
  )

  $grepOut = Join-Path $Folder "GPOReport_grep_$stamp.txt"
  foreach ($p in $patterns) {
    "===== PATTERN: $p =====" | Out-File -Append -Encoding UTF8 $grepOut
    Select-String -Path $xml -Pattern $p -Context 2,2 | ForEach-Object {
      $_.ToString()
      $_.Context.PreContext
      $_.Line
      $_.Context.PostContext
      ""
    } | Out-File -Append -Encoding UTF8 $grepOut
  }

  Write-Info "Wrote GPO grep output: $grepOut"
}

function Query-GroupChangeEvents {
  param(
    [Parameter(Mandatory=$true)][string[]]$GroupNames,
    [Parameter(Mandatory=$true)][int]$Max,
    [Parameter(Mandatory=$true)][int]$HoursBack,
    [Parameter(Mandatory=$true)][string]$Folder
  )

  if (-not $QueryGroupChangeEvents) { return }

  $since = (Get-Date).AddHours(-1 * $HoursBack)
  $ids = 4728,4729,4756,4757,4732,4733

  Write-Info "Querying Security log for group membership changes since $since (max $Max)..."
  $events = Get-WinEvent -FilterHashtable @{ LogName="Security"; Id=$ids; StartTime=$since } -MaxEvents $Max -ErrorAction SilentlyContinue

  $filtered = @()
  foreach ($e in $events) {
    foreach ($g in $GroupNames) {
      if ($e.Message -match [regex]::Escape($g)) {
        $filtered += [pscustomobject]@{
          TimeCreated = $e.TimeCreated
          EventId     = $e.Id
          GroupHit    = $g
          Message     = ($e.Message -replace "`r","")
        }
        break
      }
    }
  }

  $out = Join-Path $Folder "Security_GroupChangeEvents.txt"
  if ($filtered.Count -gt 0) {
    $filtered | Sort-Object TimeCreated -Descending | ForEach-Object {
      "-----"
      "Time: $($_.TimeCreated)"
      "EventID: $($_.EventId)"
      "Group: $($_.GroupHit)"
      $_.Message
    } | Out-File -Encoding UTF8 $out
    Write-Warn "Group change events found. Review: $out"
  } else {
    "No matching group-change events found in the selected window." | Out-File -Encoding UTF8 $out
    Write-Info "No matching group-change events found. Logged: $out"
  }
}

function Rollback-FromSnapshot {
  param(
    [Parameter(Mandatory=$true)][string]$SnapshotFolder
  )

  if (-not (Test-Path $SnapshotFolder)) {
    throw "Rollback folder does not exist: $SnapshotFolder"
  }

  $jsons = Get-ChildItem -Path $SnapshotFolder -Filter "*_direct.json" -ErrorAction Stop
  if (-not $jsons -or $jsons.Count -eq 0) {
    throw "No *_direct.json files found in rollback folder: $SnapshotFolder"
  }

  Write-Warn "ROLLBACK MODE: restoring direct membership sets from snapshot folder."
  foreach ($j in $jsons) {
    $nameGuess = ($j.BaseName -replace "_direct$","") -replace "_"," "
    $groupName = $nameGuess

    $grp = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
    if (-not $grp) {
      Write-Warn "Group not found for rollback (skipping): $groupName"
      continue
    }

    $snapshotMembers = Get-Content $j.FullName -Raw | ConvertFrom-Json
    $targetDNs = @($snapshotMembers | ForEach-Object { $_.DistinguishedName } | Where-Object { $_ })

    # Current direct members
    $current = Get-ADGroupMember -Identity $groupName -ErrorAction Stop |
      Select-Object DistinguishedName, SamAccountName, ObjectClass

    $currentDNs = @($current | ForEach-Object { $_.DistinguishedName })

    # Compute delta
    $toAdd    = $targetDNs  | Where-Object { $currentDNs -notcontains $_ }
    $toRemove = $currentDNs | Where-Object { $targetDNs  -notcontains $_ }

    Write-Info "`nRollback group: $groupName"
    Write-Info "  Will ADD:    $($toAdd.Count)"
    Write-Info "  Will REMOVE: $($toRemove.Count)"

    foreach ($dn in $toRemove) {
      Write-Host "  REMOVE DN: $dn"
      Remove-ADGroupMember -Identity $groupName -Members $dn -Confirm:$false
    }
    foreach ($dn in $toAdd) {
      Write-Host "  ADD DN:    $dn"
      Add-ADGroupMember -Identity $groupName -Members $dn
    }

    Verify-Group -GroupName $groupName
  }

  Write-Warn "Rollback complete."
}

# ---------------- MAIN ----------------

Assert-Admin
Import-Modules

$domain = Get-DomainInfo
$targets = Resolve-TargetGroups

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outFolder = Join-Path $OutputRoot "PrivGroupControl_$stamp"
Ensure-Folder $outFolder

Start-Transcript -Path (Join-Path $outFolder "transcript_$stamp.log") | Out-Null

Write-Info "Domain: $($domain.DNSRoot)"
Write-Info "Output: $outFolder"
Write-Info "Targets: $($targets -join ', ')"
Write-Info "Allowlist: $($AllowUsers -join ', ')"

try {
  if ($PSCmdlet.ParameterSetName -eq "Rollback") {
    Rollback-FromSnapshot -SnapshotFolder $RollbackFrom
    return
  }

  # Snapshot first
  $snapIndex = @()
  foreach ($g in $targets) {
    $snap = Export-GroupSnapshot -GroupName $g -Folder $outFolder
    if ($snap) { $snapIndex += $snap }
  }

  # Optional detection checks
  if ($SearchSysvolGPP) { Search-SysvolGPP -DomainDNS $domain.DNSRoot -GroupNames $targets -Folder $outFolder }
  if ($ReportGPOs)      { Report-GPOs -Folder $outFolder }
  if ($QueryGroupChangeEvents) { Query-GroupChangeEvents -GroupNames $targets -Max $EventMax -HoursBack $EventHoursBack -Folder $outFolder }

  # If not applying changes, just exit after snapshot + checks
  if (-not $Apply) {
    Write-Info "Audit-only run complete (no membership changes). Use -Apply (-WhatIf recommended first) to enforce allowlist."
    return
  }

  # Build + apply plan per group (DIRECT members only)
  foreach ($s in $snapIndex) {
    $toRemove = Build-RemovalPlan -DirectMembers $s.Direct -AllowSam $AllowUsers

    Write-Info "`nPlan for '$($s.GroupName)':"
    if ($toRemove.Count -eq 0) {
      Write-Info "  No removals required."
    } else {
      $toRemove | Select-Object ObjectClass, SamAccountName, Name | Format-Table -AutoSize | Out-String | Write-Host
    }

    Apply-RemovalPlan -GroupName $s.GroupName -ToRemove $toRemove -WhatIfMode:$WhatIf
    Verify-Group -GroupName $s.GroupName
  }

  Write-Info "Done. Snapshot + transcript saved in: $outFolder"
  Write-Info "Rollback (if needed): .\Invoke-PrivGroupControl.ps1 -RollbackFrom `"$outFolder`""
}
finally {
  Stop-Transcript | Out-Null
}
