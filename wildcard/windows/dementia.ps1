# Lovingly plagiarised and authored by @Lfgberg - https://lfgberg.org

# CONFIGURE THESE
$logPath = "C:\Logs"
$transcriptPath = Join-Path $logPath "dementia.log"

# VARIABLES TO IGNORE
$transcriptPath = "C:\dementia.log"

# Create logging directory & start transcript
New-Item -ItemType Directory -Path $logPath
Start-Transcript -Path $transcriptPath

# Network Shares
Write-Host "These are the current network shares"
[string[]]$output = Invoke-Expression "net share" # list shares

New-Item $Global:scriptPath\Logs\Shares.txt -type file | Out-Null
foreach ($str in $output)
{
    Add-Content $Global:scriptPath\Logs\Shares.txt $str
    Write-Host $str
}

# Run PrivescCheck & WinPEAS

Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit -Report C:\Logs\PrivescCheck_$($env:COMPUTERNAME) -Format HTML
# Invoke-Expression .\winPEAS.ps1 - this takes forever and sucks tbh

# TODO - run pingcastle if a DC or another AD Auditing tool