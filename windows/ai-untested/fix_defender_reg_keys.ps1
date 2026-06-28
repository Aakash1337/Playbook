<#
.SYNOPSIS
    This script resets critical Windows Defender registry keys to their
    default, secure state. This is useful for re-enabling Defender if it
    has been disabled by malware or group policy.
#>

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    Exit
}

Write-Host "--- Resetting Windows Defender Registry Keys ---"

# --- Define Registry Keys and Secure Values ---
# These paths are under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender
$defenderPolicies = @{
    # Main Defender key
    "" = @{
        "DisableAntiSpyware" = 0 # 0 = Enabled
    }
    # Real-Time Protection settings
    "Real-Time Protection" = @{
        "DisableRealtimeMonitoring" = 0 # 0 = Enabled
        "DisableBehaviorMonitoring" = 0 # 0 = Enabled
        "DisableScanOnRealtimeEnable" = 0 # 0 = Enabled
    }
    # Cloud-based protection settings (MAPS)
    "Spynet" = @{
        "SpynetReporting" = 2 # 2 = Advanced Membership
        "SubmitSamplesConsent" = 3 # 3 = Send all samples automatically
    }
}

$basePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"

# --- Apply the Registry Fixes ---
foreach ($key in $defenderPolicies.Keys) {
    $currentPath = Join-Path -Path $basePath -ChildPath $key
    
    # Create the key if it doesn't exist
    if (-not (Test-Path $currentPath)) {
        New-Item -Path $currentPath -Force | Out-Null
    }
    
    $properties = $defenderPolicies[$key]
    foreach ($name in $properties.Keys) {
        $value = $properties[$name]
        Write-Host "Setting value '$name' to '$value' in path '$currentPath'..."
        try {
            Set-ItemProperty -Path $currentPath -Name $name -Value $value -Type DWord -Force
        } catch {
            Write-Error "Failed to set registry key: $_"
        }
    }
}

Write-Host "`n[+] Windows Defender registry policies have been reset."

# --- Restart Windows Defender Service ---
$serviceName = "WinDefend"
Write-Host "[*] Attempting to restart the Windows Defender service ($serviceName)..."
try {
    Restart-Service -Name $serviceName -Force -ErrorAction Stop
    Write-Host "[+] Service '$serviceName' restarted successfully."
} catch {
    Write-Warning "Could not restart the '$serviceName' service. It may already be running or in a state that prevents restart."
    Write-Warning "A system reboot may be necessary for all changes to take full effect."
}
