<#
.SYNOPSIS
    This script audits local user accounts and provides an option to disable
    all users except for a predefined list of allowed accounts.
#>

param(
    [string[]]$AllowedUsers = @("Administrator", $env:USERNAME)
)

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator."
    # Re-launch with the same allowed users list
    $allowedUsersParam = $AllowedUsers | ForEach-Object { "'$_'" } | Join-String -Separator ","
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`" -AllowedUsers $allowedUsersParam"
    Exit
}

# --- Log All Users ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = "user_audit_${timestamp}.log"
Write-Host "[*] Logging all local user accounts to ${logFile}..."

$allUsers = Get-LocalUser

# Get group membership information
$userAudit = foreach ($user in $allUsers) {
    # Correctly get group membership for the user
    $groups = Get-LocalGroup | Where-Object {
        (Get-LocalGroupMember -Group $_).SID -contains $user.SID
    }
    $groupNames = ($groups.Name) -join ", "

    [PSCustomObject]@{
        Name           = $user.Name
        Enabled        = $user.Enabled
        LastLogon      = $user.LastLogon
        PasswordLastSet = $user.PasswordLastSet
        Description    = $user.Description
        Groups         = $groupNames
    }
}

$userAudit | Format-Table | Out-File -FilePath $logFile
Write-Host "[+] User audit complete."

# --- Disable Unwanted Users ---
Write-Host "`n[*] The following users will be kept enabled: $($AllowedUsers -join ', ')"
Write-Host "[*] All other users will be disabled."
$choice = Read-Host "Do you want to proceed with disabling users? (y/n)"

if ($choice -eq 'y') {
    $usersToDisable = $allUsers | Where-Object { $_.Name -notin $AllowedUsers -and $_.Enabled }

    if ($usersToDisable) {
        foreach ($user in $usersToDisable) {
            Write-Host "Disabling user: $($user.Name)"
            try {
                $user | Disable-LocalUser
                Write-Host " -> Successfully disabled."
            } catch {
                Write-Error " -> Failed to disable: $_"
            }
        }
    } else {
        Write-Host "No users to disable."
    }
    
    Write-Host "[+] User management complete."
} else {
    Write-Host "Aborted. No users were disabled."
}
