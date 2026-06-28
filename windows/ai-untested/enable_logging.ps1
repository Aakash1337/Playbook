<#
.SYNOPSIS
    This script enhances system logging on Windows for better security monitoring.
    It enables advanced PowerShell logging, increases the Security log size, and
    enables detailed process creation auditing.
#>

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    Exit
}

Write-Host "--- Enabling and Configuring System Logging ---"

# --- Enable Advanced PowerShell Logging ---
Write-Host "[*] Enabling advanced PowerShell logging..."
$psLogPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"
# Create the registry keys if they don't exist
if (-not (Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force }
if (-not (Test-Path "$psLogPath\ModuleLogging")) { New-Item -Path "$psLogPath\ModuleLogging" -Force }
if (-not (Test-Path "$psLogPath\ScriptBlockLogging")) { New-Item -Path "$psLogPath\ScriptBlockLogging" -Force }

# Enable Module Logging
Set-ItemProperty -Path "$psLogPath\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Force
Set-ItemProperty -Path "$psLogPath\ModuleLogging" -Name "ModuleNames" -Value "*" -Force
Write-Host "[+] PowerShell Module Logging enabled."

# Enable Script Block Logging
Set-ItemProperty -Path "$psLogPath\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Force
Write-Host "[+] PowerShell Script Block Logging enabled."

# Enable PowerShell Transcription
$transcriptPath = "C:\logs\PSTranscripts"
New-Item -ItemType Directory -Path $transcriptPath -Force
if (-not (Test-Path "$psLogPath\Transcription")) { New-Item -Path "$psLogPath\Transcription" -Force }
Set-ItemProperty -Path "$psLogPath\Transcription" -Name "EnableTranscripting" -Value 1 -Force
Set-ItemProperty -Path "$psLogPath\Transcription" -Name "OutputDirectory" -Value $transcriptPath -Force
Write-Host "[+] PowerShell Transcription enabled. Logs will be in $transcriptPath"


# --- Increase Security Log Size ---
Write-Host "[*] Increasing the size of the Security event log..."
$logName = "Security"
$maxSizeMB = 1024 # 1 GB
try {
    wevtutil sl $logName /ms:($maxSizeMB * 1024 * 1024)
    Write-Host "[+] Security log size set to ${maxSizeMB} MB."
} catch {
    Write-Error "Failed to set Security log size: $_"
}

# --- Enable Audit Process Creation ---
Write-Host "[*] Enabling Audit Process Creation..."
# This command will log event ID 4688 for every process created.
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Write-Host "[+] Audit Process Creation enabled."


Write-Host "--- System logging configuration complete ---"
Write-Host "A system restart may be required for all settings to take effect."
