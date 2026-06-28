<#
.SYNOPSIS
    This script is designed to run in the background and continuously monitor
    for suspicious system changes, such as new listening ports or new admin accounts.
    Findings are logged to a file.
#>

# --- Configuration ---
$logFile = "C:\logs\background_monitor.log"
$intervalSeconds = 60 # Check every 60 seconds

# --- Setup ---
if (-not (Test-Path (Split-Path $logFile -Parent))) {
    New-Item -ItemType Directory -Path (Split-Path $logFile -Parent)
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] $Message" | Out-File -FilePath $logFile -Append
}

Write-Log "--- Background Monitor Started ---"

# --- Initial State ---
# Get the initial set of listening ports
$initialListeners = Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort
# Get the initial list of administrator accounts
$initialAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name

Write-Log "Initial listening ports: $($initialListeners -join ', ')"
Write-Log "Initial administrators: $($initialAdmins -join ', ')"

# --- Main Monitoring Loop ---
while ($true) {
    # --- Check for New Listening Ports ---
    $currentListeners = Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort
    $newListeners = Compare-Object -ReferenceObject $initialListeners -DifferenceObject $currentListeners | Where-Object { $_.SideIndicator -eq "=>" } | Select-Object -ExpandProperty InputObject
    
    if ($newListeners) {
        foreach ($port in $newListeners) {
            $process = Get-NetTCPConnection -LocalPort $port | Select-Object -First 1 -ExpandProperty OwningProcess
            $processName = (Get-Process -Id $process).ProcessName
            Write-Log "ALERT: New listening port detected: $port (Process: $processName)"
        }
        # Update the baseline
        $initialListeners = $currentListeners
    }

    # --- Check for New Administrator Accounts ---
    $currentAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name
    $newAdmins = Compare-Object -ReferenceObject $initialAdmins -DifferenceObject $currentAdmins | Where-Object { $_.SideIndicator -eq "=>" } | Select-Object -ExpandProperty InputObject

    if ($newAdmins) {
        foreach ($admin in $newAdmins) {
            Write-Log "ALERT: New administrator account detected: $admin"
        }
        # Update the baseline
        $initialAdmins = $currentAdmins
    }

    # Wait for the next interval
    Start-Sleep -Seconds $intervalSeconds
}
