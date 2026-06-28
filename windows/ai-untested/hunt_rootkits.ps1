<#
.SYNOPSIS
    This script performs several checks to hunt for signs of rootkit activity.
    It is not a guaranteed rootkit detector but can reveal common symptoms.
#>

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator for best results."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    Exit
}

Write-Host "--- Hunting for Signs of Rootkits ---"

# --- 1. Check for Unsigned Drivers ---
Write-Host "`n[*] Checking for unsigned kernel drivers..."
try {
    # Get all drivers and check their signatures
    $drivers = Get-WmiObject Win32_SystemDriver
    $unsignedDrivers = @()

    foreach ($driver in $drivers) {
        try {
            $signature = Get-AuthenticodeSignature -FilePath $driver.PathName -ErrorAction Stop
            if ($signature.Status -ne 'Valid') {
                $unsignedDrivers += $driver
            }
        } catch {
            # Could not get signature, which is suspicious in itself.
            $unsignedDrivers += $driver
        }
    }

    if ($unsignedDrivers) {
        Write-Warning "[-] Found the following drivers with invalid signatures:"
        $unsignedDrivers | Select-Object Name, PathName, State | Format-Table -AutoSize
    } else {
        Write-Host "[+] All running drivers have valid signatures."
    }
} catch {
    Write-Error "Could not check driver signatures: $_"
}

# --- 2. Compare Process Lists (Heuristic) ---
# This is a simple heuristic. A real rootkit may hook both APIs.
Write-Host "`n[*] Comparing process lists to find discrepancies (heuristic)..."
$psProcesses = Get-Process | Select-Object -ExpandProperty Name
$wmiProcesses = Get-WmiObject -Class Win32_Process | Select-Object -ExpandProperty Name

# Compare the two lists. This is not perfect but can be an indicator.
$discrepancies = Compare-Object -ReferenceObject $psProcesses -DifferenceObject $wmiProcesses
if ($discrepancies) {
    Write-Warning "[-] Discrepancies found between PowerShell and WMI process lists:"
    $discrepancies
} else {
    Write-Host "[+] Process lists from PowerShell and WMI are consistent."
}

# --- 3. Check for Alternate Data Streams (ADS) in System32 ---
Write-Host "`n[*] Checking for Alternate Data Streams (ADS) in System32..."
Write-Host "(This can be a slow process and may have legitimate results)"
try {
    $adsFiles = Get-ChildItem -Path "$env:SystemRoot\System32" -Recurse -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' }
    if ($adsFiles) {
        Write-Warning "[-] Found files with Alternate Data Streams in System32:"
        $adsFiles | Select-Object FileName, Stream | Format-Table -AutoSize
    } else {
        Write-Host "[+] No Alternate Data Streams found in System32."
    }
} catch {
    Write-Error "Could not scan for Alternate Data Streams: $_"
}


Write-Host "`n--- Rootkit Hunt Complete ---"
Write-Host "Review any warnings above carefully."
