<#
.SYNOPSIS
    This script changes the password for all local non-system users.
    It can be run in two modes: interactive and non-interactive.
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("interactive", "non-interactive")]
    [string]$Mode = "interactive"
)

# --- Check for Administrator Privileges ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-File `"$PSCommandPath`" -Mode $Mode"
    Exit
}

# --- Script Body ---
$logFile = "password_changes.log"

# Function to generate a random password
function Generate-RandomPassword {
    param(
        [int]$Length = 16
    )
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+'
    $charArray = $chars.ToCharArray()
    $passwordChars = @()
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object 'Byte[]' ($Length)
    $rng.GetBytes($bytes)
    for ($i = 0; $i -lt $Length; $i++) {
        $index = $bytes[$i] % $charArray.Length
        $passwordChars += $charArray[$index]
    }
    $password = -join $passwordChars
    return $password
}

# Get all local users, excluding well-known system accounts
$users = Get-LocalUser | Where-Object { $_.Enabled -and $_.Name -notin ("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount") }

if ($Mode -eq "interactive") {
    foreach ($user in $users) {
        Write-Host "Changing password for $($user.Name)"
        try {
            $newPassword = Read-Host -AsSecureString "Enter new password for $($user.Name)"
            $user | Set-LocalUser -Password $newPassword
            Write-Host "Successfully changed password for $($user.Name)"
        } catch {
            Write-Error "Failed to change password for $($user.Name): $_"
        }
    }
}
elseif ($Mode -eq "non-interactive") {
    Write-Host "Changing passwords non-interactively. New passwords will be logged to $logFile"
    "--- Password Changes $(Get-Date) ---" | Out-File -FilePath $logFile -Append
    
    foreach ($user in $users) {
        $newPassword = Generate-RandomPassword
        $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
        
        try {
            $user | Set-LocalUser -Password $securePassword
            Write-Host "Successfully changed password for $($user.Name)"
            "$($user.Name): Password changed at $(Get-Date)" | Out-File -FilePath $logFile -Append
        } catch {
            Write-Error "Failed to change password for $($user.Name): $_"
        }
    }
    Write-Host "Password change events logged to $logFile (passwords NOT logged)"
}

Write-Host "Password changes complete."
