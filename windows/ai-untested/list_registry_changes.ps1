<#
.SYNOPSIS
    This script gathers information about applied Group Policies and snapshots
    key registry locations to help identify changes and persistence mechanisms.
#>

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script should be run as Administrator for best results."
}

# --- Setup ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "registry_snapshot_${timestamp}"
New-Item -ItemType Directory -Path $outputDir
Write-Host "Registry information will be saved in the '$outputDir' directory."

# --- Run gpresult ---
Write-Host "[*] Saving applied Group Policy information..."
gpresult /v | Out-File -FilePath (Join-Path $outputDir "gpresult.txt")
Write-Host "[+] gpresult output saved."

# --- Snapshot Key Registry Autorun Locations ---
Write-Host "[*] Snapshotting common registry autorun locations..."

$registryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)

foreach ($path in $registryPaths) {
    $keyName = $path.Replace(":", "")
    $outFile = Join-Path $outputDir "${keyName}.txt"
    
    if (Test-Path $path) {
        Write-Host "Snapshotting $path..."
        Get-ItemProperty -Path $path | Out-File -FilePath $outFile
    } else {
        Write-Warning "Path not found: $path"
    }
}

Write-Host "[+] Registry snapshot complete. Review the files in '$outputDir'."
