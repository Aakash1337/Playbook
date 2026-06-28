# Windows Binary Integrity Checker

A PowerShell-based forensic tool for detecting tampered, replaced, or unauthorized Windows system binaries by comparing file hashes and digital signatures against a known-good baseline.

## Overview

Modern attacks often involve replacing or modifying critical Windows executables to establish persistence, evade detection, or escalate privileges. This tool helps security professionals and system administrators detect such modifications by:

- Creating a cryptographic baseline of system binaries from a trusted source
- Verifying target systems against that baseline
- Detecting new or unexpected files that weren't in the original baseline
- Validating Microsoft Authenticode signatures

## Features

- **Hash-based integrity verification** using SHA256 (default) or SHA1
- **Authenticode signature validation** including catalog-signed files
- **Automatic OS context capture** to help explain legitimate differences due to patch levels
- **Detection of new/unexpected files** in monitored directories
- **Flexible scanning scope** from critical binaries only to full directory recursion
- **Detailed reporting** with color-coded console output and CSV export

## Requirements

- Windows PowerShell 5.1 or later
- Administrator privileges (recommended for accessing all system files)
- A known-good reference system at the same patch level as target systems

## Installation

Download the script directly:

```powershell
# Download from repository
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/YOUR_REPO/Check-MSBinaries.ps1" -OutFile "Check-MSBinaries.ps1"
```

Or clone the repository:

```bash
git clone https://github.com/YOUR_REPO/windows-binary-checker.git
cd windows-binary-checker
```

## Quick Start

### Step 1: Create a Baseline

Run on a known-good, freshly installed or trusted system:

```powershell
.\Check-MSBinaries.ps1 -Mode Baseline -OutFile .\baseline.csv
```

### Step 2: Verify a Target System

Copy the baseline file to the target system and run:

```powershell
.\Check-MSBinaries.ps1 -Mode Verify -BaselineFile .\baseline.csv -OutFile .\report.csv
```

## Usage

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Mode` | String | Yes | Operation mode: `Baseline` or `Verify` |
| `-OutFile` | String | No | Output file path (default: `.\report.csv`) |
| `-BaselineFile` | String | Verify only | Path to baseline CSV file |
| `-Paths` | String[] | No | Custom paths to scan (default: critical system binaries) |
| `-Recurse` | Switch | No | Recursively scan directories |
| `-HashAlg` | String | No | Hash algorithm: `SHA256` (default) or `SHA1` |
| `-IncludeAll` | Switch | No | Include non-Microsoft-signed files in baseline |
| `-DetectNewFiles` | Switch | No | Scan for files not present in baseline |

### Examples

**Basic baseline of critical system files:**

```powershell
.\Check-MSBinaries.ps1 -Mode Baseline -OutFile .\baseline.csv
```

**Extended baseline including System32 and SysWOW64:**

```powershell
.\Check-MSBinaries.ps1 -Mode Baseline `
    -Paths "C:\Windows\System32", "C:\Windows\SysWOW64" `
    -Recurse `
    -OutFile .\full_baseline.csv
```

**Baseline including third-party signed files:**

```powershell
.\Check-MSBinaries.ps1 -Mode Baseline -IncludeAll -OutFile .\baseline_all.csv
```

**Standard verification:**

```powershell
.\Check-MSBinaries.ps1 -Mode Verify `
    -BaselineFile .\baseline.csv `
    -OutFile .\report.csv
```

**Verification with new file detection:**

```powershell
.\Check-MSBinaries.ps1 -Mode Verify `
    -BaselineFile .\baseline.csv `
    -DetectNewFiles `
    -OutFile .\report.csv
```

**Verbose output for troubleshooting:**

```powershell
.\Check-MSBinaries.ps1 -Mode Verify `
    -BaselineFile .\baseline.csv `
    -OutFile .\report.csv `
    -Verbose
```

## How It Works

### Baseline Mode

1. **Target Resolution**: Identifies files to scan based on provided paths or default critical binary list
2. **Metadata Collection**: For each file, collects:
   - SHA256/SHA1 hash
   - Authenticode signature status and signer
   - File version information
   - File size and timestamps
3. **Filtering** (default): Keeps only Microsoft-signed, valid-signature files
4. **Export**: Writes baseline data to CSV

### Verify Mode

1. **Baseline Loading**: Imports the reference baseline CSV
2. **Algorithm Validation**: Checks hash algorithm matches baseline (auto-switches if different)
3. **File Verification**: For each baseline entry:
   - Checks file existence
   - Computes current hash
   - Validates signature
   - Compares against baseline
4. **New File Detection** (optional): Scans baseline directories for unexpected files
5. **Reporting**: Generates detailed CSV report and console summary

### Default Critical Binaries

When no custom paths are specified, the script monitors these high-value targets:

| Binary | Purpose | Why It Matters |
|--------|---------|----------------|
| `lsass.exe` | Local Security Authority | Credential storage and authentication |
| `winlogon.exe` | Windows Logon | User authentication process |
| `services.exe` | Service Control Manager | Manages Windows services |
| `svchost.exe` | Service Host | Hosts multiple Windows services |
| `csrss.exe` | Client/Server Runtime | Critical system process |
| `smss.exe` | Session Manager | First user-mode process |
| `wininit.exe` | Windows Initialization | Starts critical services |
| `explorer.exe` | Windows Shell | User interface shell |
| `cmd.exe` | Command Prompt | Command interpreter |
| `powershell.exe` | PowerShell | Script execution engine |
| `rundll32.exe` | DLL Runner | Executes DLL functions |
| `WmiPrvSE.exe` | WMI Provider | WMI operations |
| `ntfs.sys` | NTFS Driver | File system driver |
| `tcpip.sys` | TCP/IP Driver | Network stack |
| `afd.sys` | Ancillary Function Driver | Winsock support |

## Understanding Results

### Status Codes

| Status | Meaning | Action Required |
|--------|---------|-----------------|
| `OK` | File matches baseline | None |
| `HASH_MISMATCH` | File hash differs from baseline | **Investigate immediately** - may indicate tampering or legitimate update |
| `MISSING` | Baseline file not found on target | Investigate - may indicate deletion or different OS configuration |
| `SIGNATURE_INVALID` | Authenticode signature invalid | **High priority** - unsigned or tampered file |
| `SIGNATURE_SUSPICIOUS` | Valid signature but not Microsoft | Review - may be legitimate third-party or malicious replacement |
| `ERROR` | Could not process file | Check file permissions or corruption |
| `NEW_UNSIGNED` | New file without valid signature | **Investigate** - potentially malicious |
| `NEW_THIRD_PARTY` | New file signed by non-Microsoft | Review for legitimacy |
| `NEW_MS_SIGNED` | New Microsoft-signed file | Usually legitimate (updates, features) |

### Interpreting Hash Mismatches

Hash mismatches don't always indicate compromise. Common legitimate causes:

1. **Windows Updates**: Patches modify system binaries
2. **Feature Updates**: Major Windows versions replace files
3. **Hotfixes**: Security patches update specific files
4. **Different Editions**: Home vs Pro vs Enterprise may differ

The script captures OS build number and recent hotfixes to help correlate:

```
OS: Windows 11 Pro 23H2 Build 22631
Recent Hotfixes (top 10): KB5034441;KB5034204;...
```

**Best Practice**: Create baselines from systems at the same patch level as targets.

### Sample Report Output

```
======================================================================
Verification Summary
  Report file: .\report.csv

  OK                         18
  HASH_MISMATCH               2
  NEW_MS_SIGNED               3
  SIGNATURE_SUSPICIOUS        1

======================================================================

SUSPICIOUS ENTRIES (requires investigation):
----------------------------------------------------------------------
Status              Path                                    SigStatus  Signer
------              ----                                    ---------  ------
HASH_MISMATCH       C:\Windows\System32\svchost.exe        Valid      Microsoft
SIGNATURE_SUSPICIOUS C:\Windows\System32\custom.dll        Valid      Contoso Inc
```

## Advanced Usage

### Integrating with SIEM/SOAR

Export results for ingestion:

```powershell
# Generate JSON for SIEM
$results = Import-Csv .\report.csv
$results | Where-Object { $_.Status -ne "OK" } | ConvertTo-Json | Out-File alerts.json
```

### Scheduled Monitoring

Create a scheduled task for regular checks:

```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\Check-MSBinaries.ps1 -Mode Verify -BaselineFile C:\Baselines\baseline.csv -OutFile C:\Reports\daily_$(Get-Date -Format 'yyyyMMdd').csv"

$trigger = New-ScheduledTaskTrigger -Daily -At "02:00"

Register-ScheduledTask -TaskName "BinaryIntegrityCheck" `
    -Action $action -Trigger $trigger -RunLevel Highest
```

### Comparing Multiple Systems

```powershell
# Verify multiple systems against same baseline
$systems = @("Server01", "Server02", "Server03")

foreach ($system in $systems) {
    $session = New-PSSession -ComputerName $system
    
    # Copy script and baseline
    Copy-Item .\Check-MSBinaries.ps1 -ToSession $session -Destination "C:\Temp\"
    Copy-Item .\baseline.csv -ToSession $session -Destination "C:\Temp\"
    
    # Run verification
    Invoke-Command -Session $session -ScriptBlock {
        Set-Location C:\Temp
        .\Check-MSBinaries.ps1 -Mode Verify -BaselineFile .\baseline.csv -OutFile ".\report_$env:COMPUTERNAME.csv"
    }
    
    # Retrieve report
    Copy-Item -FromSession $session -Path "C:\Temp\report_$system.csv" -Destination ".\Reports\"
    
    Remove-PSSession $session
}
```

## Limitations

- **Patch Level Sensitivity**: Baselines must match target patch levels to avoid false positives
- **Catalog-Signed Files**: Some files are signed via Windows catalog rather than embedded signatures; the script handles this but behavior may vary
- **In-Use Files**: Some files may be locked during scanning
- **Memory-Only Malware**: This tool detects on-disk modifications only, not memory-resident threats
- **Sophisticated Attacks**: Advanced attackers may modify files while preserving valid signatures (e.g., DLL search order hijacking)

## Security Considerations

- **Baseline Protection**: Store baselines securely; if attackers modify your baseline, verification is meaningless
- **Offline Analysis**: For incident response, consider mounting drives offline to avoid rootkit interference
- **Chain of Custody**: Document baseline creation and maintain hash of baseline file itself
- **Regular Updates**: Recreate baselines after each patch cycle

## Troubleshooting

### "Access Denied" Errors

Run PowerShell as Administrator:

```powershell
Start-Process PowerShell -Verb RunAs
```

### Hash Algorithm Mismatch Warning

The script auto-detects and switches algorithms:

```
WARNING: Hash algorithm mismatch! Baseline uses 'SHA256', but current setting is 'SHA1'
WARNING: Switching to baseline algorithm: SHA256
```

### Get-ComputerInfo Fails

On Server Core or older systems, the script falls back to WMI automatically. If issues persist:

```powershell
# Verify WMI is working
Get-CimInstance -ClassName Win32_OperatingSystem
```

### Large Directory Scans Time Out

For extensive scans, increase PowerShell timeout or scan in batches:

```powershell
# Scan directories separately
$dirs = @("C:\Windows\System32", "C:\Windows\SysWOW64")
foreach ($dir in $dirs) {
    .\Check-MSBinaries.ps1 -Mode Baseline -Paths $dir -Recurse -OutFile ".\baseline_$($dir -replace '[:\\]','_').csv"
}
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with clear description

## License

MIT License - See LICENSE file for details.

## Acknowledgments

- Microsoft documentation on Authenticode signatures
- MITRE ATT&CK framework for technique references
- Security community for binary integrity monitoring best practices
