<#
.SYNOPSIS
    This script resets common Windows Explorer and UI-related registry keys
    to their default values. This can help fix issues caused by malware, such
    as a missing taskbar, disabled Task Manager, or no right-click menu.
#>

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
    Exit
}

Write-Host "--- Resetting Explorer and UI Registry Defaults ---"

# --- Define Registry Keys and Values to Fix ---
# We'll use a hashtable to store the path, name, and desired (default) value.
$registryFixes = @{
    # Enable Task Manager
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" = @{
        "DisableTaskMgr" = 0
    }
    # Enable Registry Editor (regedit)
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" = @{
        "DisableRegistryTools" = 0
    }
    # Enable Right-Click Context Menu
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
        "NoViewContextMenu" = 0
    }
    # Show the Start Menu and Taskbar
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
        "NoSetTaskbar" = 0
    }
    # Ensure Explorer is the default shell
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" = @{
        "Shell" = "explorer.exe"
    }
}

# --- Apply the Fixes ---
foreach ($path in $registryFixes.Keys) {
    $properties = $registryFixes[$path]
    
    # Create the key if it doesn't exist
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $properties.Keys) {
        $value = $properties[$name]
        Write-Host "Setting value '$name' to '$value' in path '$path'..."
        try {
            Set-ItemProperty -Path $path -Name $name -Value $value -Force
        } catch {
            Write-Error "Failed to set registry key: $_"
        }
    }
}

Write-Host "`n[+] Registry fixes have been applied."
Write-Host "[*] You may need to restart the 'explorer.exe' process or log off for all changes to take effect."

# --- Restart Explorer (Optional) ---
$choice = Read-Host "Do you want to restart the explorer.exe process now? (y/n)"
if ($choice -eq 'y') {
    Write-Host "Restarting explorer.exe..."
    Stop-Process -Name explorer -Force
    # It should restart automatically.
}
