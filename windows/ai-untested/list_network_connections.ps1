<#
.SYNOPSIS
    This script lists all active network connections and listening ports,
    and correlates them with the owning process. The output is saved to a file.
#>

# --- Setup ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "network_connections_${timestamp}.log"
Write-Host "Network connection information will be saved to ${logFile}"

Write-Host "--- Listing Network Connections and Listeners ---"

# --- Get TCP Connections ---
Write-Host "[*] Getting TCP connections..."
$tcpConnections = Get-NetTCPConnection | Select-Object -Property `
    LocalAddress, `
    LocalPort, `
    RemoteAddress, `
    RemotePort, `
    State, `
    OwningProcess

# Add process name to the output
$tcpReport = foreach ($conn in $tcpConnections) {
    try {
        $processName = (Get-Process -Id $conn.OwningProcess -ErrorAction Stop).ProcessName
    } catch {
        $processName = "N/A"
    }
    
    $conn | Add-Member -MemberType NoteProperty -Name ProcessName -Value $processName -PassThru
}

# --- Get UDP Endpoints (Listeners) ---
Write-Host "[*] Getting UDP listeners..."
$udpListeners = Get-NetUDPEndpoint | Select-Object -Property `
    LocalAddress, `
    LocalPort, `
    OwningProcess

# Add process name to the output
$udpReport = foreach ($listener in $udpListeners) {
    try {
        $processName = (Get-Process -Id $listener.OwningProcess -ErrorAction Stop).ProcessName
    } catch {
        $processName = "N/A"
    }
    
    $listener | Add-Member -MemberType NoteProperty -Name ProcessName -Value $processName -PassThru
}

# --- Save to Log File ---
"--- TCP Connections ($(Get-Date)) ---`n" | Out-File -FilePath $logFile
$tcpReport | Format-Table -AutoSize | Out-File -FilePath $logFile -Append

"`n--- UDP Listeners ($(Get-Date)) ---`n" | Out-File -FilePath $logFile -Append
$udpReport | Format-Table -AutoSize | Out-File -FilePath $logFile -Append

Write-Host "[+] Network connection information saved to ${logFile}"
Invoke-Item $logFile
