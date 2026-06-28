# Windows

## Gamplan

1. Complete forensic questions - you'll probably mess them up if you don't do them first
2. Read the README
3. Do any tasks from the README
4. Run the scripts
5. Configure critical services

## Before Running Scripts

1. READ THE README
2. Configure the variables at the top of `virtual-viagara.ps1` - users, RDP, etc.
3. Ensure your critical services aren't going to be messed up by the script - `CTRL + F`
4. Configure the variables at the top of `the-stigginator.ps1` - use `Get-Stig -ListAvailable` - you may (probably) need to install PowerSTIG `Install-Module -Name PowerSTIG -Force -AllowClobber -Confirm`
5. Run `cast.bat` as an admin

## Scripts

* `virtual-viagara.ps1` - big boy Windows configuration script
* `cast.bat` - a wrapper to set the execution policy and run the other scripts
* `dementia.ps1` - situational awareness script
* `the-stigginator.ps1` - a wrapper for Microsoft's PowerSTIG
* `gunking-gunkster-gunkallovertheplace.ps1` - used to run active tools that change the env such as hardeningkitty and sawh
