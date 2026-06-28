<#
.SYNOPSIS
  Log all local users, then disable all local users except an allow-list.

.DESCRIPTION
  - Exports local user inventory to CSV (before + after).
  - Writes an actions log (what would change / what changed).
  - Safety: will NOT disable the currently logged-in account.
  - By default, also protects "Administrator" unless you explicitly override protections.
  - Supports rollback mode to re-enable accounts disabled by a previous run.
  - Uses reliable Windows identity detection for anti-lockout protection.

.EXAMPLE
  # Audit only (default mode - no changes made)
  .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash")

.EXAMPLE
  # Dry run - shows what WOULD happen
  .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash") -DryRun

.EXAMPLE
  # Enforce changes
  .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash") -Enforce

.EXAMPLE
  # Enforce with confirmation prompts
  .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin","Aakash") -Enforce -Confirm

.EXAMPLE
  # Enforce and allow disabling protected accounts (DANGEROUS)
  .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin") -Enforce -OverrideProtections

.EXAMPLE
  # Rollback: re-enable accounts disabled by a previous run
  .\Disable-NonAllowedLocalUsers.ps1 -Rollback "C:\ProgramData\CCDC\UserControl\actions_20250115_143022.csv"

.EXAMPLE
  # Preview what -WhatIf would do (built-in PowerShell support)
  .\Disable-NonAllowedLocalUsers.ps1 -AllowedUsers @("CCDCAdmin") -Enforce -WhatIf

.OUTPUTS
  Returns a PSCustomObject with (normal mode):
    - Success: Boolean indicating overall success
    - DisabledCount: Number of accounts disabled
    - FailedCount: Number of accounts that failed to disable
    - AuditedCount: Total accounts processed
    - LogFile: Path to the log file
    - ActionsCsv: Path to the actions CSV

  Returns a PSCustomObject with (rollback mode):
    - Success: Boolean indicating overall success
    - RestoredCount: Number of accounts re-enabled
    - FailedCount: Number of accounts that failed to restore
    - LogFile: Path to the log file
    - RollbackCsv: Path to the rollback actions CSV
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Audit')]
param(
  [Parameter(Mandatory = $true, ParameterSetName = 'Audit', Position = 0)]
  [Parameter(Mandatory = $true, ParameterSetName = 'Enforce', Position = 0)]
  [Parameter(Mandatory = $true, ParameterSetName = 'DryRun', Position = 0)]
  [string[]] $AllowedUsers,

  [Parameter(Mandatory = $true, ParameterSetName = 'Enforce')]
  [switch] $Enforce,

  [Parameter(Mandatory = $true, ParameterSetName = 'DryRun')]
  [switch] $DryRun,

  # Rollback mode: provide path to a previous actions CSV to re-enable disabled accounts
  [Parameter(Mandatory = $true, ParameterSetName = 'Rollback')]
  [ValidateScript({ Test-Path $_ -PathType Leaf })]
  [string] $Rollback,

  # If set, you may disable even protected accounts (NOT recommended).
  [switch] $OverrideProtections,

  # Optional: extra exclusions that will never be disabled unless OverrideProtections is set.
  [string[]] $ProtectedUsers = @("Administrator"),

  # Output folder for logs/CSVs
  [string] $OutDir = "C:\ProgramData\CCDC\UserControl"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- Results tracking ---
$script:disabledCount = 0
$script:failedCount = 0
$script:auditedCount = 0

# --- Prep output paths ---
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile     = Join-Path $OutDir "disable_users_$ts.log"
$beforeCsv   = Join-Path $OutDir "local_users_before_$ts.csv"
$afterCsv    = Join-Path $OutDir "local_users_after_$ts.csv"
$actionsCsv  = Join-Path $OutDir "actions_$ts.csv"

function Write-Log {
  param(
    [string]$Msg,
    [ValidateSet('INFO', 'WARN', 'ERROR')]
    [string]$Level = 'INFO'
  )
  $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "s"), $Level, $Msg
  # Write to console
  Write-Host $line
  # Append to log file without triggering ShouldProcess
  [System.IO.File]::AppendAllText($logFile, "$line`r`n")
}

# --- Rollback Mode ---
if ($Rollback) {
  Write-Log "=== ROLLBACK MODE ==="
  Write-Log "Reading actions from: $Rollback"

  if (-not (Test-Path $Rollback)) {
    Write-Log "ERROR: Rollback file not found: $Rollback" -Level ERROR
    throw "Rollback file not found: $Rollback"
  }

  $previousActions = Import-Csv -Path $Rollback
  $disabledActions = $previousActions | Where-Object { $_.ActionTaken -eq 'DISABLED' }

  if ($disabledActions.Count -eq 0) {
    Write-Log "No DISABLED accounts found in the rollback file. Nothing to restore."
    Write-Output "No accounts to restore."
    return [pscustomobject]@{
      Success       = $true
      RestoredCount = 0
      FailedCount   = 0
      LogFile       = $logFile
    }
  }

  Write-Log "Found $($disabledActions.Count) account(s) to restore"

  $restoredCount = 0
  $rollbackFailedCount = 0
  $rollbackActions = [System.Collections.Generic.List[pscustomobject]]::new()

  foreach ($action in $disabledActions) {
    $userName = $action.User
    $rollbackResult = "NO_CHANGE"

    # Verify the account still exists
    $localUser = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
    if (-not $localUser) {
      Write-Log "SKIPPED: Account '$userName' no longer exists" -Level WARN
      $rollbackResult = "ACCOUNT_NOT_FOUND"
    } elseif ($localUser.Enabled) {
      Write-Log "SKIPPED: Account '$userName' is already enabled"
      $rollbackResult = "ALREADY_ENABLED"
    } else {
      if ($PSCmdlet.ShouldProcess($userName, "Enable local user account (rollback)")) {
        try {
          Write-Log "ENABLING: $userName"
          Enable-LocalUser -Name $userName -ErrorAction Stop
          Write-Log "ENABLED: $userName"
          $rollbackResult = "RESTORED"
          $restoredCount++
        } catch {
          $errorMsg = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
          Write-Log "FAILED to enable ${userName}: $errorMsg" -Level ERROR
          $rollbackResult = "FAILED"
          $rollbackFailedCount++
        }
      } else {
        Write-Log "SKIPPED (user declined): $userName"
        $rollbackResult = "SKIPPED_BY_USER"
      }
    }

    $rollbackActions.Add([pscustomobject]@{
      User              = $userName
      OriginalAction    = $action.ActionTaken
      OriginalTimestamp = $action.Timestamp
      RollbackResult    = $rollbackResult
      Timestamp         = (Get-Date).ToString("s")
    })
  }

  # Export rollback actions
  $rollbackCsv = Join-Path $OutDir "rollback_$ts.csv"
  $rollbackActions | Export-Csv -NoTypeInformation -Path $rollbackCsv -Confirm:$false

  Write-Log "=== ROLLBACK SUMMARY ==="
  Write-Log "Accounts restored: $restoredCount"
  Write-Log "Accounts failed: $rollbackFailedCount"
  Write-Log "Rollback actions exported to: $rollbackCsv"

  Write-Output ""
  Write-Output "Rollback complete:"
  Write-Output "  Restored: $restoredCount"
  Write-Output "  Failed:   $rollbackFailedCount"
  Write-Output "  Log:      $logFile"
  Write-Output "  Actions:  $rollbackCsv"

  $rollbackResult = [pscustomobject]@{
    Success       = ($rollbackFailedCount -eq 0)
    RestoredCount = $restoredCount
    FailedCount   = $rollbackFailedCount
    LogFile       = $logFile
    RollbackCsv   = $rollbackCsv
  }

  if ($rollbackFailedCount -gt 0) {
    $host.SetShouldExit(1)
  }

  return $rollbackResult
}

# --- Determine current interactive username (anti-lockout) ---
# Use WindowsIdentity for more reliable detection across different execution contexts
try {
  $windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $currentUser = $windowsIdentity.Name.Split('\')[-1]
} catch {
  # Fallback to environment variable
  $currentUser = $env:USERNAME
}

# Check if running as SYSTEM or another service account
$isServiceAccount = $currentUser -match '\$$' -or
                    $currentUser -eq 'SYSTEM' -or
                    $currentUser -like '*$' -or
                    $windowsIdentity.IsSystem

if ($isServiceAccount) {
  Write-Log "WARNING: Running as service account '$currentUser'. Anti-lockout protection based on current user may not apply to interactive accounts." -Level WARN
  # Try to get the logged-in console user as additional protection
  try {
    $consoleUser = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
    if ($consoleUser) {
      $consoleUserName = $consoleUser.Split('\')[-1]
      Write-Log "Detected console user: $consoleUserName - adding to protected list" -Level INFO
      $currentUser = $consoleUserName
    }
  } catch {
    Write-Log "Could not detect console user: $($_.Exception.Message)" -Level WARN
  }
}

# Normalize comparisons (case-insensitive)
$allowedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($u in $AllowedUsers) { [void]$allowedSet.Add($u) }

# ANTI-LOCKOUT: Always allow current user to avoid locking yourself out
[void]$allowedSet.Add($currentUser)

# Protected accounts that should not be disabled unless -OverrideProtections
$protectedSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($p in $ProtectedUsers) { [void]$protectedSet.Add($p) }
# ANTI-LOCKOUT: Current user is also protected
[void]$protectedSet.Add($currentUser)

Write-Log "Starting local user audit. OutDir=$OutDir"
Write-Log "CurrentUser=$currentUser (IsServiceAccount=$isServiceAccount)"
Write-Log "AllowedUsers=$($AllowedUsers -join ', ')"
Write-Log "EffectiveAllowedUsers=$([string]::Join(', ', ($allowedSet)))"
Write-Log "ProtectedUsers=$([string]::Join(', ', ($protectedSet)))"

$modeDescription = if ($DryRun) { "DRYRUN" } elseif ($Enforce) { "ENFORCE" } else { "AUDIT_ONLY" }
Write-Log "Mode: $modeDescription (OverrideProtections=$OverrideProtections)"

# --- Get local users inventory ---
if (-not (Get-Command Get-LocalUser -ErrorAction SilentlyContinue)) {
  throw "Get-LocalUser not found. This script requires Windows 10+/Server 2016+ with the LocalAccounts module."
}

$usersBefore = Get-LocalUser | Select-Object `
  Name, Enabled, Description, LastLogon, PasswordRequired, PasswordExpires, SID, PrincipalSource

$usersBefore | Export-Csv -NoTypeInformation -Path $beforeCsv -Confirm:$false
Write-Log "Exported BEFORE inventory to: $beforeCsv"

# --- Decide actions ---
$actions = [System.Collections.Generic.List[pscustomobject]]::new()

foreach ($u in $usersBefore) {
  $script:auditedCount++
  $name = $u.Name

  $isAllowed   = $allowedSet.Contains($name)
  $isProtected = $protectedSet.Contains($name)

  $shouldDisable =
    (-not $isAllowed) -and
    ($u.Enabled -eq $true) -and
    ( $OverrideProtections -or (-not $isProtected) )

  $actionResult = "NO_CHANGE"

  if ($shouldDisable) {
    if ($DryRun) {
      Write-Log "WOULD DISABLE: $name (enabled=$($u.Enabled))"
      $actionResult = "WOULD_DISABLE"
    } elseif (-not $Enforce) {
      Write-Log "WOULD DISABLE: $name (enabled=$($u.Enabled)) [audit-only mode]"
      $actionResult = "WOULD_DISABLE"
    } else {
      # Enforce mode - actually disable
      if ($PSCmdlet.ShouldProcess($name, "Disable local user account")) {
        try {
          Write-Log "DISABLING: $name"
          Disable-LocalUser -Name $name -ErrorAction Stop
          Write-Log "DISABLED: $name"
          $actionResult = "DISABLED"
          $script:disabledCount++
        } catch {
          $errorMsg = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
          Write-Log "FAILED to disable ${name}: $errorMsg" -Level ERROR
          $actionResult = "FAILED"
          $script:failedCount++
        }
      } else {
        Write-Log "SKIPPED (user declined): $name"
        $actionResult = "SKIPPED_BY_USER"
      }
    }
  } else {
    if ($VerbosePreference -eq 'Continue') {
      Write-Log "NO CHANGE: $name (Allowed=$isAllowed Protected=$isProtected Enabled=$($u.Enabled))"
    }
  }

  $action = [pscustomobject]@{
    User            = $name
    WasEnabled      = $u.Enabled
    IsAllowed       = $isAllowed
    IsProtected     = $isProtected
    ActionTaken     = $actionResult
    Mode            = $modeDescription
    Timestamp       = (Get-Date).ToString("s")
  }
  $actions.Add($action)
}

$actions | Export-Csv -NoTypeInformation -Path $actionsCsv -Confirm:$false
Write-Log "Exported actions to: $actionsCsv"

# --- Export after state ---
$usersAfter = Get-LocalUser | Select-Object `
  Name, Enabled, Description, LastLogon, PasswordRequired, PasswordExpires, SID, PrincipalSource

$usersAfter | Export-Csv -NoTypeInformation -Path $afterCsv -Confirm:$false
Write-Log "Exported AFTER inventory to: $afterCsv"

# --- Summary ---
Write-Log "=== SUMMARY ==="
Write-Log "Accounts audited: $script:auditedCount"
Write-Log "Accounts disabled: $script:disabledCount"
Write-Log "Accounts failed: $script:failedCount"
Write-Log "Done."

Write-Output ""
Write-Output "Artifacts:"
Write-Output "  Log:         $logFile"
Write-Output "  Before CSV:  $beforeCsv"
Write-Output "  Actions CSV: $actionsCsv"
Write-Output "  After CSV:   $afterCsv"

# --- Return structured result ---
$result = [pscustomobject]@{
  Success       = ($script:failedCount -eq 0)
  DisabledCount = $script:disabledCount
  FailedCount   = $script:failedCount
  AuditedCount  = $script:auditedCount
  LogFile       = $logFile
  BeforeCsv     = $beforeCsv
  AfterCsv      = $afterCsv
  ActionsCsv    = $actionsCsv
}

# Set exit code for automation
if ($script:failedCount -gt 0) {
  $host.SetShouldExit(1)
}

return $result
