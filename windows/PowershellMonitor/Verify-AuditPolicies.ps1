function Write-Status {
    param([string]$Message, [string]$Status, [string]$Color = "White")
    $symbol = switch ($Status) {
        "ENABLED" { "[OK]" }
        "DISABLED" { "[X]" }
        "ERROR" { "[!]" }
        default { "[?]" }
    }
    Write-Host "$symbol " -NoNewline -ForegroundColor $Color
    Write-Host $Message
}

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "AUDIT POLICY VERIFICATION SCRIPT" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}

Write-Host "Checking Process Creation auditing..." -ForegroundColor Yellow
Write-Host ""

$processCreationStatus = auditpol /get /subcategory:"Process Creation" 2>&1 | Out-String

if ($processCreationStatus -match "Success and Failure") {
    Write-Status "Process Creation auditing: ENABLED (Success and Failure)" "ENABLED" "Green"
} elseif ($processCreationStatus -match "Success") {
    Write-Status "Process Creation auditing: PARTIAL (Success only)" "DISABLED" "Yellow"
    Write-Host "  WARNING: Should enable both Success and Failure" -ForegroundColor Yellow
} else {
    Write-Status "Process Creation auditing: NOT ENABLED" "DISABLED" "Red"
}

Write-Host ""
Write-Host "Checking Command Line auditing..." -ForegroundColor Yellow
Write-Host ""

$cmdLineRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$cmdLineRegValue = "ProcessCreationIncludeCmdLine_Enabled"

try {
    $cmdLineReg = Get-ItemProperty -Path $cmdLineRegPath -Name $cmdLineRegValue -ErrorAction SilentlyContinue
    if ($cmdLineReg -and $cmdLineReg.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
        Write-Status "Command Line auditing: ENABLED (Registry)" "ENABLED" "Green"
    } else {
        Write-Status "Command Line auditing: NOT ENABLED" "DISABLED" "Red"
    }
} catch {
    Write-Status "Command Line auditing: NOT ENABLED" "DISABLED" "Red"
}

Write-Host ""
Write-Host "Checking File System auditing..." -ForegroundColor Yellow
Write-Host ""

$fileSystemStatus = auditpol /get /subcategory:"File System" 2>&1 | Out-String

if ($fileSystemStatus -match "Success and Failure") {
    Write-Status "File System auditing: ENABLED (Success and Failure)" "ENABLED" "Green"
} else {
    Write-Status "File System auditing: NOT ENABLED" "DISABLED" "Yellow"
}

Write-Host ""
Write-Host "Checking Logon auditing..." -ForegroundColor Yellow
Write-Host ""

$logonStatus = auditpol /get /subcategory:"Logon" 2>&1 | Out-String

if ($logonStatus -match "Success and Failure") {
    Write-Status "Logon auditing: ENABLED (Success and Failure)" "ENABLED" "Green"
} else {
    Write-Status "Logon auditing: NOT ENABLED" "DISABLED" "Yellow"
}

Write-Host ""
Write-Host "Checking Other System Events auditing (Scheduled Tasks)..." -ForegroundColor Yellow
Write-Host ""

$otherSystemStatus = auditpol /get /subcategory:"Other System Events" 2>&1 | Out-String

if ($otherSystemStatus -match "Success and Failure") {
    Write-Status "Other System Events auditing: ENABLED (Success and Failure)" "ENABLED" "Green"
} else {
    Write-Status "Other System Events auditing: NOT ENABLED" "DISABLED" "Red"
    Write-Host "  WARNING: Scheduled task events (4698, 4700, 4701, 4702) will NOT be logged!" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "GROUP POLICY CHECK" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

$gpoPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (Test-Path $gpoPath) {
    $gpoProcessCreation = Get-ItemProperty -Path $gpoPath -Name "ProcessCreation" -ErrorAction SilentlyContinue
    if ($gpoProcessCreation) {
        Write-Status "Group Policy Process Creation: Configured" "ENABLED" "Yellow"
        Write-Host "  NOTE: Group Policy may override local settings" -ForegroundColor Yellow
    }
}

$gpoAuditPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$auditBase = Get-ItemProperty -Path $gpoAuditPath -Name "AuditBaseObjects" -ErrorAction SilentlyContinue
if ($auditBase) {
    Write-Status "Audit Base Objects: $($auditBase.AuditBaseObjects)" "ENABLED" "Yellow"
}

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "VERIFICATION TEST" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Testing if Event 4688 is being generated..." -ForegroundColor Yellow
Write-Host "Running test command: cmd.exe /c echo test" -ForegroundColor Gray

$testTime = Get-Date
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "echo test" -WindowStyle Hidden -Wait

Start-Sleep -Seconds 2

try {
    $testEvents = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        ID = 4688
        StartTime = $testTime.AddSeconds(-5)
    } -MaxEvents 1 -ErrorAction SilentlyContinue
    
    if ($testEvents) {
        Write-Status "Event 4688 generation: WORKING" "ENABLED" "Green"
        $testEvent = $testEvents[0]
        Write-Host "  Found event at: $($testEvent.TimeCreated)" -ForegroundColor Gray
        
        if ($testEvent.Properties.Count -gt 8) {
            $cmdLine = $testEvent.Properties[8].Value
            if ($cmdLine) {
                Write-Status "Command line capture: WORKING" "ENABLED" "Green"
                Write-Host "  Command: $cmdLine" -ForegroundColor Gray
            } else {
                Write-Status "Command line capture: NOT WORKING" "DISABLED" "Red"
                Write-Host "  WARNING: Command line not captured in event" -ForegroundColor Red
            }
        }
    } else {
        Write-Status "Event 4688 generation: NOT WORKING" "DISABLED" "Red"
        Write-Host "  ERROR: No Event 4688 found after test command" -ForegroundColor Red
        Write-Host "  Process Creation auditing is NOT working!" -ForegroundColor Red
    }
} catch {
    Write-Status "Event 4688 generation: ERROR" "ERROR" "Red"
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Checking for recent scheduled task events (4698)..." -ForegroundColor Yellow
Write-Host ""

$recentTime = (Get-Date).AddMinutes(-30)
try {
    $taskEvents = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        ID = 4698
        StartTime = $recentTime
    } -MaxEvents 5 -ErrorAction SilentlyContinue
    
    if ($taskEvents) {
        Write-Status "Found $($taskEvents.Count) Event 4698 in last 30 minutes" "ENABLED" "Green"
        foreach ($evt in $taskEvents) {
            Write-Host "  - Event at: $($evt.TimeCreated)" -ForegroundColor Gray
            if ($evt.Properties.Count -gt 0) {
                Write-Host "    Task: $($evt.Properties[0].Value)" -ForegroundColor Gray
            }
        }
    } else {
        Write-Status "No Event 4698 found in last 30 minutes" "DISABLED" "Yellow"
        Write-Host "  NOTE: This is normal if no tasks were created recently" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Testing Event 4698 generation by creating a test task..." -ForegroundColor Yellow
        $testTaskName = "CCDC-Test-$(Get-Random)"
        
        Write-Host "  Method 1: Using schtasks.exe (command line)..." -ForegroundColor Gray
        $testTime1 = Get-Date
        try {
            $schtasksCmd = "schtasks.exe /create /tn `"$testTaskName`" /tr `"cmd.exe /c echo test`" /sc once /st `"$((Get-Date).AddMinutes(1).ToString('HH:mm'))`" /f"
            Invoke-Expression $schtasksCmd | Out-Null
            Start-Sleep -Seconds 3
            
            $testTaskEvents1 = Get-WinEvent -FilterHashtable @{
                LogName = "Security"
                ID = 4698
                StartTime = $testTime1.AddSeconds(-2)
            } -MaxEvents 1 -ErrorAction SilentlyContinue
            
            if ($testTaskEvents1) {
                Write-Status "Event 4698 generation: WORKING (schtasks.exe)" "ENABLED" "Green"
                Write-Host "  Found Event 4698 using schtasks.exe!" -ForegroundColor Green
                schtasks.exe /delete /tn $testTaskName /f 2>&1 | Out-Null
            } else {
                Write-Host "  [X] Event 4698 NOT generated with schtasks.exe" -ForegroundColor Red
                schtasks.exe /delete /tn $testTaskName /f 2>&1 | Out-Null
                
                Write-Host "  Method 2: Using PowerShell Register-ScheduledTask..." -ForegroundColor Gray
                $testTime2 = Get-Date
                $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo test"
                $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
                Register-ScheduledTask -TaskName "$testTaskName-PS" -Action $action -Trigger $trigger -Description "CCDC Test" -ErrorAction Stop | Out-Null
                Start-Sleep -Seconds 3
                
                $testTaskEvents2 = Get-WinEvent -FilterHashtable @{
                    LogName = "Security"
                    ID = 4698
                    StartTime = $testTime2.AddSeconds(-2)
                } -MaxEvents 1 -ErrorAction SilentlyContinue
                
                if ($testTaskEvents2) {
                    Write-Status "Event 4698 generation: WORKING (PowerShell)" "ENABLED" "Green"
                    Write-Host "  Found Event 4698 using PowerShell!" -ForegroundColor Green
                } else {
                    Write-Status "Event 4698 generation: NOT WORKING" "DISABLED" "Red"
                    Write-Host "  WARNING: Event 4698 not generated with either method!" -ForegroundColor Red
                    Write-Host ""
                    Write-Host "  REASON: Event 4698 may not generate on this Windows version" -ForegroundColor Yellow
                    Write-Host "  or Group Policy may be blocking it" -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "  Check manually: Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4698]]' -MaxEvents 5" -ForegroundColor Gray
                }
                
                Unregister-ScheduledTask -TaskName "$testTaskName-PS" -Confirm:$false -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
} catch {
    Write-Status "Error checking Event 4698: $($_.Exception.Message)" "ERROR" "Red"
}

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "MENU" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Check audit policies only" -ForegroundColor Yellow
Write-Host "2. Enable all audit policies" -ForegroundColor Yellow
Write-Host "3. Exit" -ForegroundColor Yellow
Write-Host ""
$choice = Read-Host "Select option (1-3)"

if ($choice -eq "3") {
    Write-Host "Exiting..." -ForegroundColor Gray
    exit 0
}

if ($choice -ne "1" -and $choice -ne "2") {
    Write-Host "Invalid option. Exiting..." -ForegroundColor Red
    exit 1
}

if ($choice -eq "1") {
    Write-Host ""
    Write-Host "Check-only mode completed." -ForegroundColor Green
    Write-Host ""
    Write-Host "To enable missing policies, run this script again and select option 2." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "ENABLING AUDIT POLICIES..." -ForegroundColor Yellow
Write-Host ""

$policiesToEnable = @(
    @{Name="Process Creation"; Include="Command Line"},
    @{Name="File System"},
    @{Name="Logon"},
    @{Name="Logoff"},
    @{Name="Account Lockout"},
    @{Name="User Account Management"},
    @{Name="Security Group Management"},
    @{Name="Audit Policy Change"},
    @{Name="Security System Extension"},
    @{Name="Other System Events"}
)

$successCount = 0
$failCount = 0

foreach ($policy in $policiesToEnable) {
    Write-Host "Enabling: $($policy.Name)..." -NoNewline -ForegroundColor Gray
    
    $result = auditpol /set /subcategory:"$($policy.Name)" /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host " SUCCESS" -ForegroundColor Green
        $successCount++
    } else {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host "  Error: $result" -ForegroundColor Red
        $failCount++
    }
    
    if ($policy.Include -and $policy.Include -eq "Command Line") {
        Write-Host "  Enabling: $($policy.Include)..." -NoNewline -ForegroundColor Gray
        $cmdLineRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        $cmdLineRegValue = "ProcessCreationIncludeCmdLine_Enabled"
        
        try {
            if (-not (Test-Path $cmdLineRegPath)) {
                New-Item -Path $cmdLineRegPath -Force | Out-Null
            }
            Set-ItemProperty -Path $cmdLineRegPath -Name $cmdLineRegValue -Value 1 -Type DWord -Force
            Write-Host " SUCCESS" -ForegroundColor Green
            $successCount++
        } catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
            $failCount++
        }
    }
}

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "VERIFICATION AFTER ENABLING" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

$finalStatus = auditpol /get /subcategory:"Process Creation" 2>&1 | Out-String
if ($finalStatus -match "Success and Failure") {
    Write-Status "Process Creation: ENABLED" "ENABLED" "Green"
} else {
    Write-Status "Process Creation: STILL NOT ENABLED" "DISABLED" "Red"
    Write-Host "  WARNING: May be blocked by Group Policy!" -ForegroundColor Red
    Write-Host "  Check: gpedit.msc -> Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy" -ForegroundColor Yellow
}

$finalCmdLineRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$finalCmdLineRegValue = "ProcessCreationIncludeCmdLine_Enabled"
try {
    $finalCmdLineReg = Get-ItemProperty -Path $finalCmdLineRegPath -Name $finalCmdLineRegValue -ErrorAction SilentlyContinue
    if ($finalCmdLineReg -and $finalCmdLineReg.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
        Write-Status "Command Line: ENABLED" "ENABLED" "Green"
    } else {
        Write-Status "Command Line: STILL NOT ENABLED" "DISABLED" "Red"
        Write-Host "  NOTE: May require reboot or gpupdate /force" -ForegroundColor Yellow
    }
} catch {
    Write-Status "Command Line: STILL NOT ENABLED" "DISABLED" "Red"
}

Write-Host ""
$finalOtherSystem = auditpol /get /subcategory:"Other System Events" 2>&1 | Out-String
if ($finalOtherSystem -match "Success and Failure") {
    Write-Status "Other System Events: ENABLED" "ENABLED" "Green"
} else {
    Write-Status "Other System Events: STILL NOT ENABLED" "DISABLED" "Red"
    Write-Host "  WARNING: Scheduled task events (4698, 4700, 4701, 4702) will NOT be logged!" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Summary: $successCount policies enabled, $failCount failed" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
Write-Host ""

if ($failCount -gt 0) {
    Write-Host "If policies failed to enable, check:" -ForegroundColor Yellow
    Write-Host "  1. Group Policy may be overriding (check gpedit.msc)" -ForegroundColor Gray
    Write-Host "  2. Domain Group Policy may be blocking" -ForegroundColor Gray
    Write-Host "  3. Run: gpupdate /force" -ForegroundColor Gray
    Write-Host "  4. Check: rsop.msc (Resultant Set of Policy)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Test again with:" -ForegroundColor Yellow
Write-Host "  .\Verify-AuditPolicies.ps1 -CheckOnly" -ForegroundColor Gray
