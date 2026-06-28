<#
.SYNOPSIS
    This script lists installed applications and attempts to identify custom or
    non-standard software by comparing against a baseline of common applications.
#>

# --- List of Common/Expected Applications ---
# This list can be customized. It includes common Windows components,
# runtimes, and widely used applications.
$commonApps = @(
    "*Microsoft Visual C++*",
    "*Microsoft .NET*",
    "*Microsoft Edge*",
    "*Microsoft Office*",
    "*Microsoft OneDrive*",
    "*Microsoft Update Health Tools*",
    "*Windows Driver Package*",
    "*Java*",
    "*Adobe Acrobat Reader*",
    "*Google Chrome*",
    "*Mozilla Firefox*",
    "*7-Zip*",
    "*Notepad++*",
    "*Wireshark*",
    "*Nmap*",
    "*Sysinternals*"
)

Write-Host "--- Identifying Custom or Non-Standard Applications ---"

# Get installed applications from the registry
# We query both 32-bit and 64-bit locations
$installedApps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
$installedApps += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*

# Filter for items that have a DisplayName
$installedApps = $installedApps | Where-Object { $_.DisplayName } | Select-Object DisplayName, Publisher, InstallDate | Sort-Object DisplayName

$customApps = @()

foreach ($app in $installedApps) {
    $isCommon = $false
    foreach ($common in $commonApps) {
        if ($app.DisplayName -like $common -or $app.Publisher -like $common) {
            $isCommon = $true
            break
        }
    }

    if (-not $isCommon) {
        $customApps += $app
    }
}

if ($customApps.Count -gt 0) {
    Write-Host "[+] Found the following potentially custom or non-standard applications:"
    $customApps | Format-Table -AutoSize
} else {
    Write-Host "[ ] No obvious custom or non-standard applications found based on the current baseline."
}

Write-Host "`n--- Full List of Installed Applications ---"
$installedApps | Format-Table -AutoSize
