<#
.SYNOPSIS
    This script specifically enables advanced PowerShell auditing features.
    It configures Module Logging, Script Block Logging, and Transcription to
    capture detailed information about all PowerShell activity on the system.
#>

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    Exit
}

Write-Host "--- Enabling Advanced PowerShell Auditing ---"

# --- Define Registry Paths ---
$psLogPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"
$moduleLogPath = "$psLogPath\ModuleLogging"
$scriptBlockLogPath = "$psLogPath\ScriptBlockLogging"
$transcriptionPath = "$psLogPath\Transcription"
$transcriptOutputDir = "C:\logs\PSTranscripts"

# --- Create Registry Keys and Transcript Directory ---
Write-Host "[*] Creating necessary registry keys and directories..."
if (-not (Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force }
if (-not (Test-Path $moduleLogPath)) { New-Item -Path $moduleLogPath -Force }
if (-not (Test-Path $scriptBlockLogPath)) { New-Item -Path $scriptBlockLogPath -Force }
if (-not (Test-Path $transcriptionPath)) { New-Item -Path $transcriptionPath -Force }
if (-not (Test-Path $transcriptOutputDir)) { New-Item -ItemType Directory -Path $transcriptOutputDir -Force }

# --- Enable Module Logging ---
# Logs pipeline execution details, including variable values.
Set-ItemProperty -Path $moduleLogPath -Name "EnableModuleLogging" -Value 1 -Force
Set-ItemProperty -Path $moduleLogPath -Name "ModuleNames" -Value "*" -Force # Log for all modules
Write-Host "[+] PowerShell Module Logging enabled for all modules."

# --- Enable Script Block Logging ---
# Logs the full content of any script block that is executed.
Set-ItemProperty -Path $scriptBlockLogPath -Name "EnableScriptBlockLogging" -Value 1 -Force
Write-Host "[+] PowerShell Script Block Logging enabled."

# --- Enable PowerShell Transcription ---
# Creates a transcript of every PowerShell session.
Set-ItemProperty -Path $transcriptionPath -Name "EnableTranscripting" -Value 1 -Force
Set-ItemProperty -Path $transcriptionPath -Name "OutputDirectory" -Value $transcriptOutputDir -Force
Set-ItemProperty -Path $transcriptionPath -Name "EnableInvocationHeader" -Value 1 -Force # Adds timestamp to commands
Write-Host "[+] PowerShell Transcription enabled. Transcripts will be saved to $transcriptOutputDir"

Write-Host "`n--- PowerShell Auditing Configuration Complete ---"
Write-Host "These settings will apply to all new PowerShell sessions."
