<#
.SYNOPSIS
    This script provides a quick situational awareness snapshot of the system,
    including logged-on users, network activity, and recent security events.
#>

# --- Setup ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "situational_awareness_${timestamp}.log"
Write-Host "Situational awareness report will be saved to ${logFile}"

# Function to write a formatted header to the log file
function Write-Header {
    param([string]$Title)
    "#" * 60 | Out-File -FilePath $logFile -Append
    "# $($Title.ToUpper())" | Out-File -FilePath $logFile -Append
    "#" * 60 | Out-File -FilePath $logFile -Append
    "" | Out-File -FilePath $logFile -Append
}

# --- Logged-On Users ---
Write-Header "Currently Logged-On Users"
query user | Out-File -FilePath $logFile -Append

# --- Network Summary ---
Write-Header "Network Summary (Established Connections)"
Get-NetTCPConnection -State Established |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
    Format-Table -AutoSize |
    Out-File -FilePath $logFile -Append

Write-Header "Listening Ports"
Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress, LocalPort, OwningProcess |
    Format-Table -AutoSize |
    Out-File -FilePath $logFile -Append

# --- Recent Security Events ---
# Getting the last 20 logon/logoff events.
Write-Header "Recent Security Logon/Logoff Events (Last 20)"
try {
    Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624 or EventID=4634]]" -MaxEvents 20 |
        Select-Object TimeCreated, Id, Message |
        Format-List |
        Out-File -FilePath $logFile -Append
} catch {
    "Could not retrieve security events. Ensure you have appropriate permissions." | Out-File -FilePath $logFile -Append
}

# --- Recently Created Processes (if auditing is enabled) ---
Write-Header "Recently Created Processes (Last 20 - requires Process Creation Auditing)"
try {
    Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" -MaxEvents 20 |
        Select-Object TimeCreated, Id, Message |
        Format-List |
        Out-File -FilePath $logFile -Append
} catch {
    "Could not retrieve process creation events. Ensure auditing is enabled." | Out-File -FilePath $logFile -Append
}


Write-Host "[+] Situational awareness report saved to ${logFile}"
Invoke-Item $logFile
