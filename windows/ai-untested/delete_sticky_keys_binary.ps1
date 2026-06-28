<#
.SYNOPSIS
    This script checks for and remediates the Sticky Keys backdoor, where sethc.exe
    is replaced by cmd.exe to provide unauthenticated access.
#>

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    Exit
}

Write-Host "--- Checking for Sticky Keys Backdoor (sethc.exe) ---"

$sethcPath = "$env:SystemRoot\System32\sethc.exe"
$cmdPath = "$env:SystemRoot\System32\cmd.exe"

if (-not (Test-Path $sethcPath)) {
    Write-Warning "sethc.exe not found at the expected location."
    Exit
}

# --- Compare Hashes ---
$sethcHash = Get-FileHash $sethcPath -Algorithm MD5
$cmdHash = Get-FileHash $cmdPath -Algorithm MD5

Write-Host "MD5 Hash of sethc.exe: $($sethcHash.Hash)"
Write-Host "MD5 Hash of cmd.exe:   $($cmdHash.Hash)"

if ($sethcHash.Hash -eq $cmdHash.Hash) {
    Write-Warning "[-] sethc.exe has the same hash as cmd.exe! This is a backdoor."
    Write-Host "[*] Attempting to remediate..."

    # --- Remediation ---
    # Take ownership of the file
    Write-Host "Taking ownership of $sethcPath..."
    takeown /f $sethcPath
    
    # Grant administrators full control
    Write-Host "Granting Administrators full control..."
    icacls $sethcPath /grant administrators:F

    # Try to restore the file using System File Checker
    Write-Host "Running System File Checker to restore the original sethc.exe..."
    sfc /scanfile=$sethcPath
    
    # Verify the hash again
    $newSethcHash = Get-FileHash $sethcPath -Algorithm MD5
    if ($newSethcHash.Hash -ne $cmdHash.Hash) {
        Write-Host "[+] Remediation successful. sethc.exe has been restored."
        Write-Host "New MD5 Hash: $($newSethcHash.Hash)"
    } else {
        Write-Error "Remediation failed. Manual intervention is required."
    }

} else {
    Write-Host "[+] Hashes do not match. No evidence of this specific backdoor."
}
