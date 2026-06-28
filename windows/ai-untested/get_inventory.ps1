<#
.SYNOPSIS
    This script gathers a comprehensive inventory of a Windows system.
    It collects information about the OS, hardware, network, software, users,
    and more, saving it to a timestamped directory for analysis.
#>

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script should be run as Administrator for best results."
}

# --- Setup ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "inventory_${timestamp}"
New-Item -ItemType Directory -Path $outputDir
Write-Host "System inventory will be saved in the '$outputDir' directory."

# Function to run a command and save its output
function Run-And-Log {
    param(
        [string]$Command,
        [string]$OutFile
    )
    $fullPath = Join-Path $outputDir $OutFile
    Add-Content -Path $fullPath -Value "--- Running: $Command ---"
    Invoke-Expression $Command | Out-File -FilePath $fullPath -Append
    Add-Content -Path $fullPath -Value "`n`n"
}


# --- System Information ---
Write-Host "[*] Gathering basic system information..."
Run-And-Log "Get-ComputerInfo" "system_info.txt"
Run-And-Log "systeminfo" "system_info.txt"

# --- Hardware Information ---
Write-Host "[*] Gathering hardware information..."
Run-And-Log "Get-WmiObject -Class Win32_Processor" "hardware_info.txt"
Run-And-Log "Get-WmiObject -Class Win32_PhysicalMemory" "hardware_info.txt"
Run-And-Log "Get-Disk" "hardware_info.txt"
Run-And-Log "Get-PnpDevice" "hardware_info.txt"

# --- Network Information ---
Write-Host "[*] Gathering network information..."
Run-And-Log "Get-NetIPAddress" "network_info.txt"
Run-And-Log "Get-NetRoute" "network_info.txt"
Run-And-Log "Get-NetTCPConnection" "network_info.txt"
Run-And-Log "ipconfig /all" "network_info.txt"

# --- Users and Groups ---
Write-Host "[*] Gathering user and group information..."
Run-And-Log "Get-LocalUser" "users_groups.txt"
Run-And-Log "Get-LocalGroup" "users_groups.txt"
Run-And-Log "net user" "users_groups.txt"
Run-And-Log "query user" "users_groups.txt"

# --- Services and Processes ---
Write-Host "[*] Gathering service and process information..."
Run-And-Log "Get-Process" "services_processes.txt"
Run-And-Log "Get-Service" "services_processes.txt"
Run-And-Log "schtasks /query /fo LIST /v" "services_processes.txt"

# --- Installed Software ---
Write-Host "[*] Gathering installed software information..."
Run-And-Log "Get-WmiObject -Class Win32_Product" "software.txt"
Run-And-Log "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate" "software.txt"

# --- Firewall Configuration ---
Write-Host "[*] Gathering firewall configuration..."
Run-And-Log "Get-NetFirewallProfile" "firewall.txt"
Run-And-Log "Get-NetFirewallRule -Enabled True" "firewall.txt"


Write-Host "[+] Inventory gathering complete. Results are in '$outputDir'."
