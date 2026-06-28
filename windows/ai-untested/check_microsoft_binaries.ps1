<#
.SYNOPSIS
    This script verifies the integrity of critical Microsoft system binaries
    by running the System File Checker (SFC). This helps detect if any
    protected system files have been corrupted or replaced.
#>

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    Exit
}

Write-Host "--- Verifying Integrity of Microsoft Binaries ---"
Write-Host "[*] This script will run System File Checker (sfc /scannow)."
Write-Host "[*] This process can take a significant amount of time."
$choice = Read-Host "Do you want to proceed? (y/n)"

if ($choice -ne 'y') {
    Write-Host "Aborted."
    Exit
}

# --- Run SFC ---
Write-Host "[*] Starting SFC scan. Please wait..."
try {
    # Start the process and wait for it to complete.
    $sfcProcess = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -PassThru -NoNewWindow
    
    if ($sfcProcess.ExitCode -eq 0) {
        Write-Host "[+] SFC scan completed successfully. No integrity violations found."
        Write-Host "For details, check the CBS.log file at $env:windir\Logs\CBS\CBS.log"
    } else {
        Write-Warning "[-] SFC scan completed with exit code $($sfcProcess.ExitCode)."
        Write-Warning "This may indicate that corrupt files were found and could not be repaired."
        Write-Warning "Review the CBS.log file for details: $env:windir\Logs\CBS\CBS.log"
    }

} catch {
    Write-Error "An error occurred while running SFC: $_"
}

Write-Host "--- Binary Integrity Check Complete ---"
