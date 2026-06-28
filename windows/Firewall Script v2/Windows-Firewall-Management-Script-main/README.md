# Windows Firewall Management Script

A comprehensive PowerShell script for managing Windows Firewall rules with backup, restore, port management, and temporary blocking capabilities.

## Overview

This script provides a menu-driven interface for Windows Firewall management, allowing administrators to configure firewall rules, manage ports, create backups, and implement temporary network blocking with automatic revert functionality.

## Features

- Display all enabled firewall rules with port information
- Block all ports and allow only essential ports
- Backup and restore firewall configurations
- Open or block specific ports (TCP/UDP)
- Temporary block/unblock all traffic with automatic revert
- Action logging to file
- Rule grouping for organized management

## Usage

```powershell
.\firewal1.ps1
```

## Menu Options

**1. Block all and allow essential ports**
- Creates a backup of current rules first (use option 3 to restore later)
- Sets default inbound/outbound to Block for all profiles
- **Removes** all existing firewall rules that are not in the CCDC-Lockdown group (so only essential-port rules remain)
- Creates allow rules for essential ports (from `essential-ports.json` if present, otherwise the built-in default list)
- Configures HTTP, HTTPS, DNS, LDAP, RDP, ICMP, and other services per your config or defaults

**2. Backup Only**
- Creates a timestamped backup of the **entire** firewall policy (all rules and their enabled/disabled state)
- Saves to `C:\FirewallBackups\FirewallRulesBackup_YYYYMMDD_HHMMSS.wfw`
- Restore (option 3) replaces the current policy with the backup and recreates every rule

**3. Restore to a saved backup**
- Lists all available backup files in `C:\FirewallBackups\`
- Prompts for the backup filename to restore
- **Replaces** the current firewall policy with the backup (full policy: all rules and their enabled/disabled state are recreated)
- Use this to bring back rules that were removed by option 1

**4. Open a rule for allowing a port**
- Creates inbound and outbound allow rules for specified port
- Supports TCP and UDP protocols
- Validates port number (1-65535)
- Prevents duplicate rule creation

**5. Open a rule for blocking a port**
- Creates inbound and outbound block rules for specified port
- Supports TCP and UDP protocols
- Validates port number (1-65535)
- Prevents duplicate rule creation

**6. Temporary block/unblock all traffic**
- Saves **current** firewall state to `TEMP_BLOCK_LAST.wfw` (overwrites any existing file so revert restores exactly what you had when you activated block)
- Disables all firewall rules and sets default inbound/outbound to Block
- Unblock (option 6 again) restores from that saved state
- Includes 5-second delay before activation (Ctrl+C to abort)

**7. Exit**
- Exits the script

## Essential Ports Config (optional)

When using option 1 (Block all and allow essential ports), the script loads the port list as follows:

- **If `essential-ports.json` exists** in the same folder as the script, it reads that file and uses those ports.
- **If the file is missing or invalid**, it uses the built-in default list.

**Config file location:** Same directory as the script (e.g. `C:\...\Windows-Firewall-Management-Script\essential-ports.json`).

**Format:** JSON array of objects with `Port`, `Protocol` (TCP or UDP), and `Name` (display name for the rule):

```json
[
  { "Port": 80, "Protocol": "TCP", "Name": "HTTP" },
  { "Port": 443, "Protocol": "TCP", "Name": "HTTPS" },
  { "Port": 53, "Protocol": "TCP", "Name": "DNS-TCP" }
]
```

Copy `essential-ports.example.json` to `essential-ports.json` and edit it to customize which ports are allowed when you run option 1.

## Essential Ports (default list)

When no config file is present, option 1 uses this default list:

- HTTP (80/TCP) - Web traffic
- HTTPS (443/TCP) - Secure web traffic
- DNS (53/TCP, 53/UDP) - Domain name resolution
- NTP (123/UDP) - Network time protocol
- SMTP (25/TCP) - Email sending
- POP3 (110/TCP) - Email receiving
- LDAP (389/TCP, 389/UDP) - Directory services
- LDAPS (636/TCP) - Secure LDAP
- SMB (445/TCP) - File sharing
- RDP (3389/TCP) - Remote desktop
- Splunk Web (8000/TCP) - Splunk web interface
- Splunk Logs (9997/TCP) - Splunk log forwarding
- ICMP - Ping and network diagnostics

## Temporary Block Feature

Option 6 provides a temporary block/unblock function designed for emergency network isolation:

**When Blocking:**
1. Removes any existing `TEMP_BLOCK_LAST.wfw` so the export always succeeds and captures the **current** state
2. Saves current firewall state to `C:\FirewallBackups\TEMP_BLOCK_LAST.wfw`
3. Disables all existing firewall rules
4. Sets default inbound/outbound actions to Block for all profiles
5. Creates marker file `TEMP_BLOCK_ACTIVE.txt` to track active state
6. All network traffic is blocked

**When Unblocking:**
1. Imports `TEMP_BLOCK_LAST.wfw` (replaces current policy with the state saved when you activated block)
2. Removes marker file
3. Network connectivity restored to the exact state you had before blocking

**Important Notes:**
- You may lose remote access when temporary block is active
- Ensure physical or console access before using temporary block
- The 5-second delay allows cancellation with Ctrl+C
- Revert restores **exactly** the rules you had when you pressed 6 (state file is overwritten each time you activate block)

## Port Rule Creation

**Inbound Rules:**
- Use LocalPort parameter (traffic coming TO this machine)

**Outbound Rules:**
- Use RemotePort parameter (traffic going FROM this machine TO remote destinations)
- This is the correct configuration for most outbound allow scenarios

The script automatically uses the appropriate port parameter based on direction.

## Logging

All firewall operations are logged to `C:\FirewallScriptLog.txt` with timestamps. Log entries include:
- Backup creation and restoration
- Port rule creation (allow/block)
- Temporary block activation and deactivation
- Rule modifications
- Error messages

## Rule Grouping

Rules created by this script are assigned to the **CCDC-Lockdown** group. Option 1 removes every rule whose group is *not* CCDC-Lockdown, then creates only the essential-port allow rules in that group. So after option 1, only CCDC-Lockdown rules exist. Use option 3 (Restore) to bring back the removed rules from a backup.

## Requirements

- Administrator privileges
- Windows Firewall service running
- PowerShell 5.1 or later
- Windows Server 2016/2019/2022 or Windows 10/11

## File Locations

**Script directory** (same folder as `firewal1.ps1`):
- `essential-ports.json` – optional; if present, option 1 uses this list of ports (create from `essential-ports.example.json`)
- `essential-ports.example.json` – example config; copy to `essential-ports.json` to customize

**Backup directory:** `C:\FirewallBackups\`
- Backup files: `FirewallRulesBackup_YYYYMMDD_HHMMSS.wfw`
- Temporary block state: `TEMP_BLOCK_LAST.wfw` (overwritten each time you activate option 6)
- Temporary block marker: `TEMP_BLOCK_ACTIVE.txt`

**Log file:**
- `C:\FirewallScriptLog.txt` – format: `[YYYY-MM-DD HH:mm:ss] Message`

## Security Considerations

1. **Backup Files**: Firewall backup files (.wfw) contain complete firewall configurations. Protect these files with appropriate permissions.

2. **Temporary Block**: The temporary block feature will disconnect all network traffic. Ensure physical or console access before activation.

3. **Rule Precedence**: Block rules take precedence over allow rules. Ensure proper rule ordering for complex configurations.

4. **Default Actions**: Setting default actions to Block provides strong security but may break legitimate applications. Test configurations in non-production environments first.

5. **Remote Access**: Blocking all traffic will terminate remote sessions. Use temporary block feature with caution on remote systems.

## Troubleshooting

**Script cannot modify firewall rules:**
- Verify you are running as Administrator
- Check Windows Firewall service is running: `Get-Service mpssvc`
- Verify no Group Policy restrictions on firewall management
- Check for third-party firewall software conflicts

**Backup restore fails:**
- Verify backup file exists and is not corrupted
- Check file permissions on backup directory
- Ensure backup file was created on same or compatible Windows version
- Try manual restore: `netsh advfirewall import <backup-file>`

**Temporary block cannot be reverted:**
- Check if state file exists: `C:\FirewallBackups\TEMP_BLOCK_LAST.wfw`
- If state file is missing, use option 3 to restore from a backup (e.g. one created before option 1 or 6)
- Check firewall service is running

**Temporary block revert restored old/wrong rules:**
- The script now removes the existing state file before saving, so the saved state is always your **current** rules when you press 6. If you still see old rules after unblock, ensure you are running the updated script and that no error occurred during "Saving current firewall rules..." (e.g. "Cannot create a file when that file already exists" is avoided by overwriting the file first).

**Port rules not working:**
- Verify rule was created: `Get-NetFirewallRule | Where-Object DisplayName -like "*Port-*"`
- Check rule is enabled: `Get-NetFirewallRule | Where-Object DisplayName -like "*Port-*" | Select-Object DisplayName, Enabled`
- Verify correct port number and protocol
- Check for conflicting rules with higher priority

**Rules not appearing in display:**
- Display shows only enabled rules
- Check if rules are disabled: `Get-NetFirewallRule | Where-Object Enabled -eq False`
- Verify rule creation succeeded (check log file)

## Examples

**Create backup before making changes:**
```
Select option: 2
Backup successful! Rules saved at C:\FirewallBackups\FirewallRulesBackup_20260116_120000.wfw
```

**Allow port 8080 for web application:**
```
Select option: 4
Enter the port number to allow: 8080
Enter the protocol (TCP/UDP): TCP
Port 8080 has been opened.
```

**Block port 445 to prevent SMB access:**
```
Select option: 5
Enter the port number to block: 445
Enter the protocol (TCP/UDP): TCP
Port 445 has been blocked.
```

**Temporary network isolation:**
```
Select option: 6
This will temporarily DISABLE all firewall rules and block ALL inbound/outbound traffic. You may lose remote access. Continue? (Y/N): Y
Saving current firewall rules so we can revert later...
Disabling ALL firewall rules...
Turning firewall ON and setting default inbound/outbound to BLOCK (all profiles)...
Temporary block is ACTIVE. Everything should be blocked in/out.
```

## Advanced Usage

**View all rules created by this script:**
```powershell
Get-NetFirewallRule -Group "CCDC-Lockdown"
```

**Remove all rules created by this script:**
```powershell
Get-NetFirewallRule -Group "CCDC-Lockdown" | Remove-NetFirewallRule -Confirm:$false
```

**Export current firewall configuration manually:**
```powershell
netsh advfirewall export C:\FirewallBackups\ManualBackup.wfw
```

**Import firewall configuration manually:**
```powershell
netsh advfirewall import C:\FirewallBackups\ManualBackup.wfw
```

## Version Information

- Designed for Windows Server 2016, 2019, 2022
- Compatible with Windows 10, Windows 11
- Requires PowerShell 5.1 or later
