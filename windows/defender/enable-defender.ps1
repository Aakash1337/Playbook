# Ensure script runs elevated
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Script must be run as Administrator"
    exit 1
}

function Invoke-Step {
    param(
        [string]$Description,
        [ScriptBlock]$Action
    )

    Write-Host "[+] $Description" -ForegroundColor Cyan
    try {
        & $Action
        Write-Host "    Success" -ForegroundColor DarkGreen
    } catch {
        Write-Warning "    Failed: $($_.Exception.Message)"
    }
}

function Show-DefenderStatus {
    param(
        [string]$Caption
    )

    Write-Host $Caption -ForegroundColor Cyan
    try {
        Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, BehaviorMonitorEnabled, NISSignatureVersion
    } catch {
        Write-Warning "    Unable to query Defender status: $($_.Exception.Message)"
    }
}

Show-DefenderStatus "Checking current Microsoft Defender protection status..."

Invoke-Step "Ensure Windows Defender service is running" {
    Set-Service -Name WinDefend -StartupType Automatic -ErrorAction Stop
    if ((Get-Service -Name WinDefend -ErrorAction Stop).Status -ne 'Running') {
        Start-Service -Name WinDefend -ErrorAction Stop
    }
}

Invoke-Step "Enable real-time monitoring" {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
}

Invoke-Step "Enable behavior monitoring" {
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop
}

Invoke-Step "Enable script scanning" {
    Set-MpPreference -DisableScriptScanning $false -ErrorAction Stop
}

Invoke-Step "Enable cloud-delivered protection" {
    Set-MpPreference -MAPSReporting Advanced -CloudBlockLevel High -ErrorAction Stop
}

Invoke-Step "Update Microsoft Defender signatures" {
    Update-MpSignature -ErrorAction Stop
}

Show-DefenderStatus "Re-checking status after applying settings..."

Write-Host "Microsoft Defender real-time protection tasks completed." -ForegroundColor Green
