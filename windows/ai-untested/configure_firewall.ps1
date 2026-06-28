<#
.SYNOPSIS
    This script configures the Windows Defender Firewall with a secure baseline policy.
    It enables the firewall for all profiles, sets default actions, and logs dropped packets.
#>

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    Exit
}

Write-Host "--- Configuring Windows Defender Firewall ---"

# --- Enable Firewall for All Profiles ---
Write-Host "[*] Enabling firewall for Domain, Private, and Public profiles..."
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
Write-Host "[+] Firewall enabled for all profiles."

# --- Set Default Actions ---
# Block incoming connections by default, and allow outgoing.
Write-Host "[*] Setting default firewall actions (Block Inbound, Allow Outbound)..."
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultOutboundAction Allow
Write-Host "[+] Default actions set."

# --- Enable Logging ---
$logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
Write-Host "[*] Enabling logging of dropped packets to ${logPath}..."
Set-NetFirewallProfile -Profile Domain, Private, Public -LogFileName $logPath
Set-NetFirewallProfile -Profile Domain, Private, Public -LogDroppedPackets True
Write-Host "[+] Logging enabled."

# --- Add Rules for Common Services (Examples) ---
# It's important to be careful with which rules you add.
# Only allow what is necessary for the competition.

Write-Host "[*] Ensuring Remote Desktop is allowed (example rule)..."
# This rule is often already present but we ensure it's enabled.
Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Enable-NetFirewallRule

# You could add other rules here, for example for a web server:
# New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80

# --- Display Firewall Status ---
Write-Host "[*] Current Firewall Status:"
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction


Write-Host "--- Firewall configuration complete ---"
