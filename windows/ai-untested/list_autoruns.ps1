<#
.SYNOPSIS
    This script runs the Sysinternals Autoruns command-line tool (autorunsc.exe)
    to generate a comprehensive list of all autostarting applications, services,
    and drivers. The output is saved to a CSV file for analysis.
#>

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator to get complete results."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    Exit
}

# --- Check for autorunsc.exe ---
if (-not (Get-Command autorunsc.exe -ErrorAction SilentlyContinue)) {
    Write-Error "autorunsc.exe not found in your PATH."
    Write-Error "Please run the 'install_tools.ps1' script to install the Sysinternals Suite,"
    Write-Error "or manually download it and add it to your system's PATH."
    Exit
}

# --- Setup ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "autoruns_scan_${timestamp}.csv"
Write-Host "Autoruns scan results will be saved to ${outputFile}"

Write-Host "--- Running Autoruns Scan ---"
Write-Host "[*] This may take a few moments..."

# --- Run Autorunsc ---
# -a *: Show all entries
# -c: Format output as CSV
# -h: Include hashes of the binaries
# -s: Verify digital signatures
# -accepteula: Automatically accept the EULA on first run
try {
    $arguments = "-a * -c -h -s -accepteula"
    $process = Start-Process -FilePath "autorunsc.exe" -ArgumentList $arguments -RedirectStandardOutput $outputFile -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -eq 0) {
        Write-Host "[+] Autoruns scan complete."
        Write-Host "Results saved to ${outputFile}"
        
        # Open the resulting CSV file
        Invoke-Item $outputFile
    } else {
        Write-Warning "[-] Autorunsc completed with exit code $($process.ExitCode)."
    }

} catch {
    Write-Error "An error occurred while running autorunsc.exe: $_"
}
