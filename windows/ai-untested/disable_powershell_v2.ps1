<#
.SYNOPSIS
    This script disables Windows PowerShell v2, an outdated version that lacks
    modern security features. This is a recommended security hardening measure.
#>

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    Exit
}

Write-Host "--- Disabling Windows PowerShell v2 ---"

# The feature name for the PowerShell v2 engine
$featureName = "MicrosoftWindowsPowerShellV2"

# --- Check the Current Status of the Feature ---
Write-Host "[*] Checking status of PowerShell v2 feature..."
try {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName
    
    if ($feature.State -eq 'Disabled') {
        Write-Host "[+] Windows PowerShell v2 is already disabled."
        Exit
    } else {
        Write-Host "[*] Windows PowerShell v2 is currently enabled. Disabling it now..."
    }

    # --- Disable the Feature ---
    # The -NoRestart switch prevents an automatic reboot.
    Disable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart
    
    # Verify the change
    $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureName
    if ($feature.State -eq 'Disabled') {
        Write-Host "[+] Successfully disabled Windows PowerShell v2."
        Write-Host "[*] A restart is required for the change to be fully effective."
    } else {
        Write-Error "Failed to disable PowerShell v2. Current state: $($feature.State)"
    }

} catch {
    Write-Error "An error occurred: $_"
    Write-Error "This command may not be available on all versions of Windows."
}
