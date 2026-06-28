<#
.SYNOPSIS
    This script installs a collection of useful security and administration tools for Windows.
    It is intended for use in CCDC competitions. It uses Chocolatey for package management.
#>

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator."
    # Re-launch the script as an Administrator
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    Exit
}

# --- Install Chocolatey (if not already installed) ---
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Chocolatey not found. Installing..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
} else {
    Write-Host "Chocolatey is already installed."
}


# --- Tools to Install ---
$tools = @(
    "sysinternals",      # Sysinternals Suite
    "wireshark",         # Network protocol analyzer
    "nmap",              # Network scanner
    "procmon",           # Process Monitor (part of Sysinternals, but good to have explicitly)
    "autoruns",          # Autoruns for Windows (part of Sysinternals)
    "7zip",              # File archiver
    "notepadplusplus"    # Advanced text editor
)

Write-Host "--- Installing Tools with Chocolatey ---"
foreach ($tool in $tools) {
    Write-Host "Installing $tool..."
    choco install $tool -y
}


# --- Manual Download for Tools not on Chocolatey ---
$toolsDir = "C:\ccdc-tools"
New-Item -ItemType Directory -Force -Path $toolsDir
Set-Location $toolsDir

# Example: PowerSploit (a collection of PowerShell modules)
Write-Host "Downloading PowerSploit..."
Invoke-WebRequest -Uri "https://github.com/PowerShellMafia/PowerSploit/archive/refs/heads/master.zip" -OutFile "PowerSploit.zip"
Expand-Archive -Path "PowerSploit.zip" -DestinationPath .
Remove-Item "PowerSploit.zip"


Write-Host "--- Tool installation complete ---"
Write-Host "Tools have been installed to their default locations and to ${toolsDir}"
