<#
.SYNOPSIS
    This script downloads and runs PingCastle to perform an Active Directory
    security health check. It is intended for use on domain-joined machines.
#>

# --- Check for Domain Membership ---
if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -ne $true) {
    Write-Warning "This machine is not joined to an Active Directory domain."
    Write-Warning "PingCastle is an AD auditing tool and will not be effective."
    $choice = Read-Host "Do you want to continue anyway? (y/n)"
    if ($choice -ne 'y') {
        Exit
    }
}

# --- Configuration ---
$toolsDir = "C:\ccdc-tools\PingCastle"
$downloadUrl = "https://github.com/vletoux/pingcastle/releases/latest/download/PingCastle.zip"
$zipFile = Join-Path $toolsDir "PingCastle.zip"
$executablePath = Join-Path $toolsDir "PingCastle.exe"

# --- Create Tools Directory ---
if (-not (Test-Path $toolsDir)) {
    New-Item -ItemType Directory -Force -Path $toolsDir
}

# --- Download and Extract PingCastle ---
if (-not (Test-Path $executablePath)) {
    Write-Host "--- Downloading PingCastle ---"
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile -UseBasicParsing
        Write-Host "[+] Download complete."
        
        Write-Host "[*] Extracting PingCastle..."
        Expand-Archive -Path $zipFile -DestinationPath $toolsDir -Force
        
        # Clean up the zip file
        Remove-Item $zipFile
    } catch {
        Write-Error "Failed to download or extract PingCastle: $_"
        Exit
    }
} else {
    Write-Host "[*] PingCastle executable already exists."
}


# --- Run PingCastle Healthcheck ---
Write-Host "`n--- Running PingCastle Healthcheck ---"
Write-Host "[*] This will generate an interactive HTML report."

if (Test-Path $executablePath) {
    try {
        # The --healthcheck parameter runs a standard audit.
        # The --server parameter targets the current user's logon server.
        # The report will be generated in the same directory.
        & $executablePath --healthcheck --server $env:LOGONSERVER
        
        Write-Host "`n[+] PingCastle scan complete."
        Write-Host "An HTML report has been generated in the directory: $toolsDir"
        
        # Open the directory in Explorer
        Invoke-Item $toolsDir
    } catch {
        Write-Error "An error occurred while running PingCastle: $_"
    }
} else {
    Write-Error "PingCastle.exe not found at the expected location."
}
