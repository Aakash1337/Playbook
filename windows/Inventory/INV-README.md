# Get-WindowsInventory.ps1 - CCDC Enhanced Edition v2.2

## 🎯 Overview

This is a **CCDC-ready** Windows system inventory and threat detection script designed specifically for Collegiate Cyber Defense Competition teams. It provides comprehensive system baselining, automated threat detection, integrated baseline comparison, and actionable security recommendations.

## 🆕 CCDC Enhancements (v2.2)

### ⭐ NEW: Integrated Baseline Comparison

The script now includes **built-in baseline comparison**! No need for a separate comparison tool:

- **Automatic Workflow**: First run creates baseline, subsequent runs auto-compare
- **Inline Display**: Changes displayed directly in HTML report with expandable tables
- **Detailed CSVs**: Full comparison data exported to CSV files
- **Easy Updates**: Use `-UpdateBaseline` flag to refresh baseline after hardening
- **Custom Paths**: Support for custom baseline locations with `-BaselinePath`

**What's Compared:**
- Processes (added/removed)
- Services (added/removed)
- Scheduled Tasks (added/removed)
- Users (added/removed)
- **Administrators** (added/removed) ⚠️ HIGH PRIORITY
- Software (added/removed)
- Autoruns (added/removed)
- Network Shares (added/removed)

**Baseline Commands:**
```powershell
# First run - creates baseline automatically
.\Get-WindowsInventory.ps1

# Subsequent runs - auto-compares with baseline
.\Get-WindowsInventory.ps1

# After hardening - update the baseline
.\Get-WindowsInventory.ps1 -UpdateBaseline

# Custom baseline location
.\Get-WindowsInventory.ps1 -BaselinePath "C:\CCDC\baseline"
```

## 🔍 CCDC Enhancements (v2.1)

### Automated Threat Detection

The script now includes intelligent threat detection for:

- **Suspicious Processes**: Detects processes running from unusual locations (temp, appdata, public), double-extension executables, and potentially malicious script interpreters
- **Suspicious Services**: Identifies auto-start services in user directories, SYSTEM services from suspicious paths, and services using encoded commands
- **Suspicious Scheduled Tasks**: Flags tasks with hidden PowerShell, encoded commands, or non-Microsoft tasks in Microsoft folders
- **Suspicious Network Connections**: Identifies connections to common C2 ports (4444, 1337, etc.) and unusual processes making network connections
- **Unauthorized Administrators**: Detects potentially unauthorized members of the Administrators group
- **Security Weaknesses**: Checks for disabled UAC, enabled RDP, disabled Windows Firewall, disabled Windows Defender, and enabled Guest accounts
- **Recent System File Modifications**: Tracks changes to critical system directories in the last 24 hours

### Enhanced Reporting

- **Threat Summary Section**: The HTML report now includes a prominent threat analysis section at the top with color-coded warnings
- **Console Output**: Immediate threat summary displayed when script completes
- **CSV Exports**: All suspicious items are exported to easy-to-review CSV files with the prefix `threat_`
- **Actionable Recommendations**: Each finding includes specific remediation steps

## 🚀 Quick Start for CCDC

### Basic Usage (Recommended for Competition)

```powershell
# First run - creates baseline automatically!
powershell -ExecutionPolicy Bypass -File .\Get-WindowsInventory.ps1 -Quick

# Subsequent runs - auto-compares with baseline!
powershell -ExecutionPolicy Bypass -File .\Get-WindowsInventory.ps1 -Quick

# Run with compression for easy transfer
powershell -ExecutionPolicy Bypass -File .\Get-WindowsInventory.ps1 -Quick -Compress

# After hardening - update baseline
powershell -ExecutionPolicy Bypass -File .\Get-WindowsInventory.ps1 -UpdateBaseline
```

**💡 Baseline Magic:** The script automatically creates a baseline on first run and compares against it on subsequent runs. No manual diffing needed!

### Advanced Usage

```powershell
# Custom output location with event logs
.\Get-WindowsInventory.ps1 -OutputRoot C:\CCDC\Inventory -IncludeEventLogs

# Quick scan without software/firewall enumeration
.\Get-WindowsInventory.ps1 -Quick -Software:$false -Firewall:$false

# Full scan with compression and event logs
.\Get-WindowsInventory.ps1 -IncludeEventLogs -Compress
```

## 🔄 New: Inventory Diffing

The toolkit now includes **Compare-WindowsInventory.ps1** for detecting changes between inventory snapshots!

### Quick Diff Example

```powershell
# Take baseline at start of competition
.\Get-WindowsInventory.ps1 -Quick -OutputRoot C:\CCDC\Baseline

# 30 minutes later, take another snapshot
.\Get-WindowsInventory.ps1 -Quick

# Compare them
.\Compare-WindowsInventory.ps1 -BaselinePath C:\CCDC\Baseline\Inventory_* -CurrentPath .\Inventory_*
```

The diff tool will:
- ✅ Identify all new/removed processes, services, tasks, users, autoruns
- ✅ Flag suspicious changes (High/Medium/Low risk)
- ✅ Generate HTML report with color-coded warnings
- ✅ Export CSV files for each change category
- ✅ Highlight critical changes (new admins, suspicious services, C2 connections)

### What Gets Compared

- **Processes**: New/removed processes (flags suspicious paths)
- **Services**: New/removed services (flags auto-start from user dirs)
- **Scheduled Tasks**: New/removed tasks (flags encoded PowerShell)
- **Users**: New/removed accounts
- **Group Members**: New/removed members (especially Administrators)
- **Software**: New/removed applications
- **Autoruns**: New/removed startup items
- **Network Connections**: New/removed connections (flags C2 ports)
- **Patches**: New/removed hotfixes
- **Network Shares**: New/removed shares

## 📋 CCDC Workflow

### 1. Initial System Baseline (First 15 minutes)

```powershell
# Run on all systems as soon as competition starts
# This automatically creates your baseline!
.\Get-WindowsInventory.ps1 -Quick -Compress
```

**Priority Actions:**
1. Review the threat summary in the console output
2. Open the HTML report (`system_report.html`) and check the "CCDC THREAT ANALYSIS" section
3. Address any **CRITICAL** security weaknesses immediately (Defender, Firewall, UAC)
4. Review `threat_suspicious_*.csv` files for immediate threats
5. **Note**: First run automatically creates `./baseline/` folder

### 2. Investigate Threats (Next 30 minutes)

Review these files in order of priority:

1. **`security_weaknesses.csv`**: Fix critical issues first (disabled Defender, disabled Firewall)
2. **`threat_unauthorized_admins.csv`**: Remove unauthorized administrator accounts
3. **`threat_suspicious_processes.csv`**: Kill malicious processes
4. **`threat_suspicious_services.csv`**: Stop and disable malicious services
5. **`threat_suspicious_connections.csv`**: Identify C2 connections and block them
6. **`threat_suspicious_tasks.csv`**: Disable or remove malicious scheduled tasks
7. **`recent_system_modifications_24h.csv`**: Check for backdoored system files

### 3. System Hardening & Baseline Update

After cleaning up threats and hardening:
```powershell
# Update baseline to reflect clean, hardened state
.\Get-WindowsInventory.ps1 -UpdateBaseline
```

This refreshes your baseline so future scans compare against the **hardened** system!

### 4. Periodic Monitoring (Every 30-60 minutes)

```powershell
# Re-run to detect new changes (compares with baseline automatically!)
.\Get-WindowsInventory.ps1 -Quick
```

**The script automatically:**
- Compares current state with baseline
- Shows changes inline in HTML report
- Exports detailed comparison CSVs
- Displays top changes in console

**Review in HTML Report:**
- **"BASELINE COMPARISON"** section shows all changes
- Click expandable sections to see added/removed items
- Green = Added, Red = Removed
- Full details displayed in tables

**What to look for:**
- New administrator accounts (⚠️ **HIGH PRIORITY**)
- New auto-start services from suspicious locations
- New scheduled tasks with encoded commands
- New network connections to unusual ports
- New autoruns in Run/Startup keys
- Removed security software or monitoring tools

## 🔍 Understanding Threat Detection

### Suspicious Processes

The script flags processes that:
- Run from temporary directories (`%TEMP%`, `%APPDATA%\Local\Temp`, `C:\Users\Public`)
- Are script interpreters (PowerShell, cmd, wscript, etc.) - **Note**: These may be legitimate
- Have double extensions (e.g., `invoice.pdf.exe`)

**Action**: Review each process. Legitimate admin tools may be flagged, so use judgment.

### Suspicious Services

The script flags services that:
- Auto-start from user directories
- Run as SYSTEM from suspicious locations
- Use encoded PowerShell commands

**Action**: Stop and disable suspicious services immediately.

### Suspicious Network Connections

The script flags connections to:
- Common C2 ports: 4444, 5555, 6666, 7777, 8888, 1337, 31337
- Unusual processes making network connections (notepad, calc, mspaint)

**Action**: Identify the process, kill it, block the IP in the firewall.

### Security Weaknesses

The script checks:
- **UAC**: Should be enabled (EnableLUA = 1)
- **RDP**: Should be disabled unless needed
- **Windows Firewall**: Should be enabled for all profiles
- **Windows Defender**: Real-time protection and antivirus should be enabled
- **Guest Account**: Should be disabled

**Action**: Fix all Critical and High-risk issues immediately.

### Unauthorized Administrators

**IMPORTANT**: Customize the legitimate admin list in the script!

Edit line ~352 in the script:
```powershell
$legitimateAdmins = @(
  'Administrator',
  'Domain Admins',
  'Enterprise Admins',
  'YourTeamUsername1',  # Add your team accounts here
  'YourTeamUsername2'
)
```

**Action**: Remove any unauthorized accounts from the Administrators group immediately.

## 📊 Output Files

### Critical Threat Files (Review First)
- `security_weaknesses.csv` - Configuration vulnerabilities
- `threat_suspicious_processes.csv` - Potentially malicious processes
- `threat_suspicious_services.csv` - Potentially malicious services
- `threat_suspicious_connections.csv` - Suspicious network connections
- `threat_unauthorized_admins.csv` - Unexpected administrator accounts
- `threat_suspicious_tasks.csv` - Suspicious scheduled tasks
- `recent_system_modifications_24h.csv` - Recent changes to system files

### Standard Inventory Files
- `system_report.html` - Main report with threat analysis (OPEN THIS FIRST)
- `inventory.json` - Machine-readable summary
- `collection.log` - Execution log with errors
- `csv/` - Directory containing all detailed CSV exports
- `artifacts/` - Text artifacts (netstat, route, arp, systeminfo, etc.)

## ⚙️ Customization for Your Environment

### 1. Customize Legitimate Administrators

Edit the `Test-UnauthorizedAdmin` function (~line 348):

```powershell
$legitimateAdmins = @(
  'Administrator',
  'Domain Admins',
  'Enterprise Admins',
  'ccdc-team1',      # Your team accounts
  'ccdc-team2',
  'backup-admin'
)
```

### 2. Adjust Suspicious Path Detection

Edit detection functions to match your environment:
- `Test-SuspiciousProcess` (~line 276)
- `Test-SuspiciousService` (~line 300)
- `Get-RecentFileModifications` (~line 366)

### 3. Add Custom C2 Ports

Edit `Get-SuspiciousNetworkConnections` (~line 399):

```powershell
if ($conn.RemotePort -in @(4444, 5555, 6666, 7777, 8888, 31337, 1337, 8080, 9999)) {
  # Add your known malicious ports
}
```

## 📊 Using Compare-WindowsInventory.ps1

### Basic Usage

```powershell
# Compare two inventory snapshots
.\Compare-WindowsInventory.ps1 -BaselinePath .\Inventory_SERVER_20250115_100000 -CurrentPath .\Inventory_SERVER_20250115_110000

# Using wildcards (picks first match)
.\Compare-WindowsInventory.ps1 -BaselinePath C:\CCDC\Baseline\Inventory_* -CurrentPath .\Inventory_*

# Custom output location
.\Compare-WindowsInventory.ps1 -BaselinePath .\Old\Inventory_* -CurrentPath .\New\Inventory_* -OutputPath C:\CCDC\Diffs
```

### Understanding the Output

**Console Output:**
- Summary of all changes (+Added / -Removed)
- Count of suspicious changes (High/Medium risk)
- Direct link to suspicious changes CSV

**HTML Report (diff_report.html):**
- Prominent "SUSPICIOUS CHANGES DETECTED" section (red background)
- Change metrics with visual indicators
- Detailed comparison table
- Links to all CSV files

**CSV Files (in csv/ folder):**
- `suspicious_changes_summary.csv` - All flagged changes with risk levels
- `diff_processes_added.csv` - New processes
- `diff_services_added.csv` - New services
- `diff_scheduled_tasks_added.csv` - New scheduled tasks
- `diff_users_added.csv` - New user accounts
- `diff_group_members_added.csv` - New group memberships (check Administrators!)
- `diff_autoruns_added.csv` - New startup items
- `diff_connections_added.csv` - New network connections
- `diff_software_added.csv` - New installed software
- `diff_shares_added.csv` - New network shares
- `diff_patches_added.csv` - New patches/hotfixes
- *(Also includes `*_removed.csv` for each category)*

### Suspicion Levels

**High Risk (Red):**
- Processes from temp/appdata/public directories
- Auto-start services from user directories
- SYSTEM services from suspicious paths
- Scheduled tasks with encoded/hidden PowerShell
- Network connections to C2 ports (4444, 1337, etc.)
- New members added to Administrators group

**Medium Risk (Yellow):**
- Script interpreters (PowerShell, cmd, wscript) - *May be legitimate*
- New user accounts
- New autoruns in Run/Startup keys
- New network shares
- Unusual processes with network connections

**Low Risk (Blue):**
- Standard processes/services
- Expected software installations

### CCDC Diff Workflow

**Step 1: Immediate Review**
```powershell
# Open the HTML report first
Invoke-Item .\InventoryDiff_*\diff_report.html
```

**Step 2: Prioritize High Risk**
```powershell
# View all suspicious changes
Import-Csv .\InventoryDiff_*\csv\suspicious_changes_summary.csv | Where-Object SuspicionLevel -eq "High" | Format-Table
```

**Step 3: Investigate Categories**
```powershell
# Check new administrators (CRITICAL)
Import-Csv .\InventoryDiff_*\csv\diff_group_members_added.csv | Where-Object Group -match "Admin"

# Check new services
Import-Csv .\InventoryDiff_*\csv\diff_services_added.csv | Format-Table

# Check new scheduled tasks
Import-Csv .\InventoryDiff_*\csv\diff_scheduled_tasks_added.csv | Format-Table
```

**Step 4: Take Action**
- Kill malicious processes
- Stop and disable malicious services
- Remove unauthorized admin accounts
- Disable malicious scheduled tasks
- Block suspicious network connections

### Example Suspicious Findings

**New Administrator Account:**
```
Category: GroupMember
Change: Added
Item: hackerman → Administrators
SuspicionLevel: High
```
**Action:** `net localgroup Administrators hackerman /delete`

**New Auto-Start Service:**
```
Category: Service
Change: Added
Item: WindowsUpdateHelper (WinUpdate)
Details: Path: C:\Users\Public\svchost.exe, StartMode: Auto
SuspicionLevel: High
```
**Action:**
```powershell
Stop-Service WinUpdate
sc.exe delete WinUpdate
Remove-Item C:\Users\Public\svchost.exe -Force
```

**New Network Connection to C2 Port:**
```
Category: NetworkConnection
Change: Added
Item: powershell.exe → 192.168.1.100:4444
SuspicionLevel: High
```
**Action:**
```powershell
# Find and kill the process
Get-Process powershell | Where-Object {$_.Id -eq <PID>} | Stop-Process -Force

# Block the IP
New-NetFirewallRule -DisplayName "Block-C2" -Direction Outbound -RemoteAddress 192.168.1.100 -Action Block
```

## 🛡️ CCDC Defense Checklist

Use these tools as part of your defense strategy:

- [ ] Run inventory on all systems within first 15 minutes (creates baseline automatically!)
- [ ] Review threat analysis section immediately
- [ ] Fix all CRITICAL security weaknesses
- [ ] Remove unauthorized administrator accounts
- [ ] Kill suspicious processes
- [ ] Stop suspicious services
- [ ] Block suspicious network connections
- [ ] Disable suspicious scheduled tasks
- [ ] Review recent file modifications
- [ ] After threat cleanup, run with `-UpdateBaseline` to reset baseline
- [ ] Re-run periodically to detect changes (compares automatically!)
- [ ] Review BASELINE COMPARISON section in HTML report
- [ ] Check expandable tables for added/removed items
- [ ] Review comparison CSV files for details
- [ ] Investigate administrator changes (highest priority!)
- [ ] Document all findings in incident log

## ⚡ Performance Tips

### Quick Mode
Use `-Quick` to skip:
- AppX package enumeration
- Full firewall rule export
- Certificate enumeration

**Execution Time**: ~30-60 seconds (vs 2-5 minutes full scan)

### Minimal Mode
For fastest results:
```powershell
.\Get-WindowsInventory.ps1 -Quick -Software:$false -Firewall:$false -Certs:$false
```

**Execution Time**: ~15-30 seconds

### Background Execution
Run on multiple systems simultaneously:
```powershell
# On remote systems
Invoke-Command -ComputerName Server1,Server2,Server3 -FilePath .\Get-WindowsInventory.ps1 -ArgumentList "-Quick"
```

## 🔒 Security Considerations

1. **Output Protection**: The script outputs to the current directory by default. Use `-OutputRoot` to specify a secure location not accessible to red team.

2. **Execution Policy**: The script uses `Bypass` which is appropriate for CCDC. This does not weaken system security.

3. **Admin Rights**: Run as Administrator for complete coverage. The script will work with limited rights but will miss some data.

4. **Network Transfer**: If transferring results off-system, use `-Compress` and secure channels.

## 🐛 Troubleshooting

### "Access Denied" Errors
- Run as Administrator
- Check if antivirus is blocking execution
- Review `collection.log` for specific errors

### Missing Data
- Some cmdlets require PowerShell 5.1+ (Windows 10/Server 2016+)
- Older systems fall back to WMI and legacy commands
- Check `collection.log` for details

### High False Positives
- Customize detection functions for your environment
- Review and adjust suspicious path patterns
- Update legitimate administrator list

## 📚 Additional Resources

### Quick Reference Commands

```powershell
# View threat summary
Import-Csv .\csv\threat_*.csv | Format-Table

# Count threats by category
Get-ChildItem .\csv\threat_*.csv | ForEach-Object {
  [PSCustomObject]@{
    Type = $_.Name
    Count = (Import-Csv $_.FullName).Count
  }
}

# Find critical weaknesses
Import-Csv .\csv\security_weaknesses.csv | Where-Object Risk -eq 'Critical'
```
