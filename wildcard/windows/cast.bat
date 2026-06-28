@echo off
echo WARNING: Running these scripts could modify critical system settings and potentially break the machine.
echo Ensure you have configured all variables properly before proceeding.
echo.
set /p "confirm=Have you reviewed the configuration and understand the risks? (y/n): "

if /i "%confirm%"=="y" (
    echo Proceeding with script execution...
    powershell.exe -ExecutionPolicy Unrestricted -File "virtual-viagara.ps1"
    start the-hardener.cmd
    powershell.exe -ExecutionPolicy Unrestricted -File "gunking-gunkster-gunkallovertheplace.ps1"
    powershell.exe -ExecutionPolicy Unrestricted -File "dementia.ps1"
    powershell.exe -ExecutionPolicy Unrestricted -File "the-stigginator.ps1"
) else (
    echo Operation canceled. Please review the configuration before proceeding.
    exit /b
)