param(
    [string]$ConfigPath = ".\CCDC-Monitor-Config.json",
    [string]$LogPath = "",
    [switch]$SetupAudit,
    [switch]$RunOnce,
    [switch]$TestMode,
    [int]$CheckInterval = 60
)

$Script:Config = @{
    EventIDs = @{
        Logon = @(4624, 4625, 4648, 4672, 4627, 4634, 4647, 4768, 4769, 4776)
        Process = @(4688, 4689, 4696)
        File = @(4660, 4661, 4663, 4656, 4658, 4699, 4654, 4670)
        Account = @(4720, 4722, 4724, 4726, 4728, 4732, 4733, 4756, 4735, 4737, 4740, 4767, 4782)
        Service = @(7045, 4697, 7034, 7035, 7036, 7040)
        Policy = @(4719, 4738, 4904, 4905, 4907, 4912)
        Network = @(5156, 5157, 5158, 5159)
        ScheduledTask = @(4698, 4700, 4701, 4702)
        ScheduledTaskOperational = @(106, 140, 141, 200, 201)
        PowerShell = @(4103, 4104, 4105, 4106)
        ObjectAccess = @(4654, 4670, 4907)
        Registry = @(4657)
    }
    SuspiciousProcesses = @(
        "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", 
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "bitsadmin.exe", "wmic.exe", "schtasks.exe", "at.exe"
    )
    NoiseFilters = @{
        Users = @("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "SERVICE")
        Paths = @("SRU.chk", "LogFiles", "wbem", "Microsoft\\Windows\\PowerShell", "Microsoft\\Windows\\AppReadiness")
    }
    LookbackMinutes = 5
    SystemName = $env:COMPUTERNAME
    Domain = "CCDCTEAM.COM"
    SeenEvents = @{}
}

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "INITIAL SETUP" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $ConfigPath)) {
    Write-Host "Config file not found at: $ConfigPath" -ForegroundColor Yellow
} else {
    Write-Host "Config file found at: $ConfigPath" -ForegroundColor Green
}
$newConfigPath = Read-Host "Enter config file path (or press Enter to use: $ConfigPath)"
if (-not [string]::IsNullOrWhiteSpace($newConfigPath)) {
    $ConfigPath = $newConfigPath
}

if (Test-Path $ConfigPath) {
    try {
        $Script:Config = Get-Content $ConfigPath | ConvertFrom-Json | ConvertTo-Hashtable
        Write-Host "[OK] Loaded configuration from: $ConfigPath" -ForegroundColor Green
    } catch {
        Write-Host "[X] Error loading config file: $($_.Exception.Message). Using default configuration." -ForegroundColor Red
    }
} else {
    Write-Host "[X] Config file not found. Using default configuration." -ForegroundColor Yellow
}

Write-Host ""
$defaultLogPath = ".\SecurityMonitor_$(Get-Date -Format 'yyyyMMdd').log"
if ([string]::IsNullOrWhiteSpace($LogPath)) {
    Write-Host "Log file path not specified." -ForegroundColor Yellow
} else {
    Write-Host "Log file path specified: $LogPath" -ForegroundColor Green
}
$userLogPath = Read-Host "Enter log file path (or press Enter for default: $defaultLogPath)"
if (-not [string]::IsNullOrWhiteSpace($userLogPath)) {
    $LogPath = $userLogPath
} else {
    if ([string]::IsNullOrWhiteSpace($LogPath)) {
        $LogPath = $defaultLogPath
    }
}

Write-Host ""
$defaultVerifyPath = ".\Verify-AuditPolicies.ps1"
if (-not (Test-Path $defaultVerifyPath)) {
    Write-Host "Verify script not found at: $defaultVerifyPath" -ForegroundColor Yellow
} else {
    Write-Host "Verify script found at: $defaultVerifyPath" -ForegroundColor Green
}
$verifyPath = Read-Host "Enter verify script path (or press Enter for default: $defaultVerifyPath)"
if ([string]::IsNullOrWhiteSpace($verifyPath)) {
    $verifyPath = $defaultVerifyPath
}
$Script:VerifyScriptPath = $verifyPath

Write-Host ""

$logDirectory = Split-Path -Path $LogPath -Parent
if (-not [string]::IsNullOrWhiteSpace($logDirectory) -and -not (Test-Path $logDirectory)) {
    try {
        New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
        Write-Host "[OK] Created log directory: $logDirectory" -ForegroundColor Green
    } catch {
        Write-Host "[X] Warning: Could not create log directory: $logDirectory" -ForegroundColor Yellow
        Write-Host "Logs will only be displayed on screen." -ForegroundColor Yellow
        $LogPath = ""
    }
}

$Script:LogFilePath = $LogPath
Write-Host "[OK] Log file will be saved to: $LogPath" -ForegroundColor Green
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "SUCCESS" { "Green" }
        "CRITICAL" { "Red" }
        default { "White" }
    }
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host "[$Level] " -NoNewline -ForegroundColor $color
    Write-Host $Message
    
    if ($Script:LogFilePath -and -not [string]::IsNullOrWhiteSpace($Script:LogFilePath)) {
        try {
            $logEntry = "[$timestamp] [$Level] $Message"
            Add-Content -Path $Script:LogFilePath -Value $logEntry -ErrorAction SilentlyContinue
        } catch {
        }
    }
}

function Get-EventField {
    param(
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event,
        [string]$FieldName
    )
    
    try {
        $xml = [xml]$Event.ToXml()
        $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace("ns", "http://schemas.microsoft.com/win/2004/08/events/event")
        
        $field = $xml.SelectSingleNode("//ns:$FieldName", $ns)
        if ($field) {
            return $field.InnerText
        }
    } catch {}
    
    return $null
}

function Get-UserFromSID {
    param([string]$SID)
    
    if ([string]::IsNullOrWhiteSpace($SID) -or $SID -eq "-") {
        return "N/A"
    }
    
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        return $objUser.Value
    } catch {
        return $SID
    }
}

function Get-EventDetails {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)
    
    $details = @{
        Time = $Event.TimeCreated
        EventID = $Event.Id
        Level = $Event.LevelDisplayName
        Source = $Event.ProviderName
        Machine = $Event.MachineName
        Message = $Event.Message
        User = "N/A"
        IPAddress = "N/A"
        ProcessName = "N/A"
        FilePath = "N/A"
        AccessMask = "N/A"
        RecordId = $Event.RecordId
    }
    
    try {
        $xml = [xml]$Event.ToXml()
        $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace("ns", "http://schemas.microsoft.com/win/2004/08/events/event")
        
        switch ($Event.Id) {
            4624 {
                $details.User = Get-EventField -Event $Event -FieldName "TargetUserName"
                $details.IPAddress = Get-EventField -Event $Event -FieldName "IpAddress"
                if ($details.User -eq "N/A") {
                    $sid = Get-EventField -Event $Event -FieldName "TargetUserSid"
                    if ($sid) { $details.User = Get-UserFromSID -SID $sid }
                }
            }
            4625 {
                $details.User = Get-EventField -Event $Event -FieldName "TargetUserName"
                $details.IPAddress = Get-EventField -Event $Event -FieldName "IpAddress"
                if ($details.User -eq "N/A") {
                    $sid = Get-EventField -Event $Event -FieldName "TargetUserSid"
                    if ($sid) { $details.User = Get-UserFromSID -SID $sid }
                }
            }
            4688 {
                $details.ProcessName = Get-EventField -Event $Event -FieldName "NewProcessName"
                $details.FilePath = Get-EventField -Event $Event -FieldName "NewProcessName"
                $details.User = Get-EventField -Event $Event -FieldName "SubjectUserName"
                $cmdLine = Get-EventField -Event $Event -FieldName "CommandLine"
                if ($cmdLine) {
                    $details.Message += " | Command: $cmdLine"
                }
                if ($details.User -eq "N/A") {
                    $sid = Get-EventField -Event $Event -FieldName "SubjectUserSid"
                    if ($sid) { $details.User = Get-UserFromSID -SID $sid }
                }
            }
            4663 {
                $details.FilePath = Get-EventField -Event $Event -FieldName "ObjectName"
                $details.User = Get-EventField -Event $Event -FieldName "SubjectUserName"
                $details.AccessMask = Get-EventField -Event $Event -FieldName "AccessMask"
                $accesses = Get-EventField -Event $Event -FieldName "Accesses"
                if ($accesses) {
                    $details.Message += " | Access: $accesses"
                }
                if ($details.User -eq "N/A") {
                    $sid = Get-EventField -Event $Event -FieldName "SubjectUserSid"
                    if ($sid) { $details.User = Get-UserFromSID -SID $sid }
                }
            }
            4660 {
                $details.FilePath = Get-EventField -Event $Event -FieldName "ObjectName"
                $details.User = Get-EventField -Event $Event -FieldName "SubjectUserName"
                if ($details.User -eq "N/A") {
                    $sid = Get-EventField -Event $Event -FieldName "SubjectUserSid"
                    if ($sid) { $details.User = Get-UserFromSID -SID $sid }
                }
            }
            4654 {
                $details.FilePath = Get-EventField -Event $Event -FieldName "ObjectName"
                $details.User = Get-EventField -Event $Event -FieldName "SubjectUserName"
                if ($details.User -eq "N/A") {
                    $sid = Get-EventField -Event $Event -FieldName "SubjectUserSid"
                    if ($sid) { $details.User = Get-UserFromSID -SID $sid }
                }
            }
            4670 {
                $details.FilePath = Get-EventField -Event $Event -FieldName "ObjectName"
                $details.User = Get-EventField -Event $Event -FieldName "SubjectUserName"
                if ($details.User -eq "N/A") {
                    $sid = Get-EventField -Event $Event -FieldName "SubjectUserSid"
                    if ($sid) { $details.User = Get-UserFromSID -SID $sid }
                }
            }
            4657 {
                $details.FilePath = Get-EventField -Event $Event -FieldName "ObjectName"
                $details.User = Get-EventField -Event $Event -FieldName "SubjectUserName"
                $valueName = Get-EventField -Event $Event -FieldName "ObjectValueName"
                if ($valueName) {
                    $details.Message += " | Value: $valueName"
                }
                if ($details.User -eq "N/A") {
                    $sid = Get-EventField -Event $Event -FieldName "SubjectUserSid"
                    if ($sid) { $details.User = Get-UserFromSID -SID $sid }
                }
            }
            4698 {
                $taskName = Get-EventField -Event $Event -FieldName "TaskName"
                if ($taskName) {
                    $details.Message += " | Task: $taskName"
                }
                $details.User = Get-EventField -Event $Event -FieldName "SubjectUserName"
                if ($details.User -eq "N/A") {
                    $sid = Get-EventField -Event $Event -FieldName "SubjectUserSid"
                    if ($sid) { $details.User = Get-UserFromSID -SID $sid }
                }
            }
            4907 {
                $details.User = Get-EventField -Event $Event -FieldName "SubjectUserName"
                if ($details.User -eq "N/A") {
                    $sid = Get-EventField -Event $Event -FieldName "SubjectUserSid"
                    if ($sid) { $details.User = Get-UserFromSID -SID $sid }
                }
            }
            4648 {
                $details.User = Get-EventField -Event $Event -FieldName "SubjectUserName"
                $targetServer = Get-EventField -Event $Event -FieldName "TargetServerName"
                if ($targetServer) {
                    $details.Message += " | Target: $targetServer"
                }
                if ($details.User -eq "N/A") {
                    $sid = Get-EventField -Event $Event -FieldName "SubjectUserSid"
                    if ($sid) { $details.User = Get-UserFromSID -SID $sid }
                }
            }
        }
        
        if ($details.User -eq "N/A") {
            $userProps = $Event.Properties | Where-Object { $_.Value -match '.*\\.*' -or $_.Value -match '@.*' }
            if ($userProps) {
                $details.User = $userProps[0].Value
            }
        }
    } catch {
        Write-Log "Error extracting event details for Event ID $($Event.Id): $($_.Exception.Message)" "WARNING"
    }
    
    return $details
}

function Write-AlertToLog {
    param(
        [array]$Events,
        [string]$AlertType = "Security Event"
    )
    
    if (-not $Script:LogFilePath -or [string]::IsNullOrWhiteSpace($Script:LogFilePath)) {
        return
    }
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "`n" + ("=" * 100)
        $logEntry += "`n$AlertType - $($Events.Count) Event(s) - $timestamp"
        $logEntry += "`nSystem: $($Script:Config.SystemName) | Domain: $($Script:Config.Domain)"
        $logEntry += "`n" + ("-" * 100) + "`n"
        
        foreach ($evt in $Events) {
            $logEntry += "`nEvent ID: $($evt.EventID) | Level: $($evt.Level)"
            $logEntry += "`nTime: $($evt.Time.ToString('yyyy-MM-dd HH:mm:ss'))"
            $logEntry += "`nUser: $($evt.User)"
            
            if ($evt.IPAddress -ne "N/A") {
                $logEntry += " | IP: $($evt.IPAddress)"
            }
            
            if ($evt.ProcessName -ne "N/A") {
                $logEntry += "`nProcess: $($evt.ProcessName)"
            }
            
            if ($evt.FilePath -ne "N/A" -and $evt.FilePath -ne $evt.ProcessName) {
                $logEntry += "`nPath: $($evt.FilePath)"
            }
            
            if ($evt.EventID -eq 4688 -and $evt.Message -match "\| Command:\s*(.+)") {
                $logEntry += "`nCommand: $($matches[1].Trim())"
            }
            
            if ($evt.Reasons -and $evt.Reasons.Count -gt 0) {
                $logEntry += "`nFlags: $($evt.Reasons -join ', ')"
            }
            
            $messageLines = $evt.Message -split "`n" | Select-Object -First 3
            $logEntry += "`nDetails: $($messageLines -join ' | ')"
            $logEntry += "`n" + ("-" * 100)
        }
        
        $logEntry += "`n" + ("=" * 100) + "`n"
        Add-Content -Path $Script:LogFilePath -Value $logEntry -ErrorAction SilentlyContinue
    } catch {
    }
}

function Show-Alert {
    param(
        [array]$Events,
        [string]$AlertType = "Security Event"
    )
    
    $isSuspicious = $AlertType -match "SUSPICIOUS"
    $separator = "".PadRight(100, "=")
    $dashLine = "".PadRight(100, "-")
    
    Write-Host ""
    Write-Host $separator -ForegroundColor Cyan
    if ($isSuspicious) {
        Write-Host "$AlertType - $($Events.Count) Event(s)" -ForegroundColor Red -BackgroundColor Yellow
    } else {
        Write-Host "$AlertType - $($Events.Count) Event(s)" -ForegroundColor Yellow
    }
    Write-Host $separator -ForegroundColor Cyan
    Write-Host "System: " -NoNewline -ForegroundColor Gray
    Write-Host $Script:Config.SystemName -ForegroundColor White
    Write-Host "Time: " -NoNewline -ForegroundColor Gray
    Write-Host (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -ForegroundColor White
    Write-Host "Domain: " -NoNewline -ForegroundColor Gray
    Write-Host $Script:Config.Domain -ForegroundColor White
    Write-Host $dashLine -ForegroundColor DarkGray
    Write-Host ""
    
    Write-AlertToLog -Events $Events -AlertType $AlertType
    
    foreach ($event in $Events) {
        $eventColor = if ($isSuspicious) { "Red" } else { "Yellow" }
        Write-Host "Event ID: " -NoNewline -ForegroundColor $eventColor
        Write-Host "$($event.EventID)" -ForegroundColor White
        Write-Host "Level: " -NoNewline -ForegroundColor Gray
        Write-Host "$($event.Level)" -ForegroundColor White
        Write-Host "Time: " -NoNewline -ForegroundColor Gray
        Write-Host "$($event.Time.ToString('MM/dd/yyyy HH:mm:ss'))" -ForegroundColor White
        Write-Host "User: " -NoNewline -ForegroundColor Gray
        Write-Host "$($event.User)" -ForegroundColor White
        
        if ($event.IPAddress -ne "N/A") {
            Write-Host "IP Address: " -NoNewline -ForegroundColor Gray
            Write-Host "$($event.IPAddress)" -ForegroundColor White
        }
        
        if ($event.ProcessName -ne "N/A") {
            Write-Host "Process: " -NoNewline -ForegroundColor Gray
            if ($event.ProcessName -in $Script:Config.SuspiciousProcesses) {
                Write-Host "$($event.ProcessName) [SUSPICIOUS]" -ForegroundColor Red
            } else {
                Write-Host "$($event.ProcessName)" -ForegroundColor White
            }
        }
        
        if ($event.FilePath -ne "N/A" -and $event.FilePath -ne $event.ProcessName) {
            Write-Host "Path: " -NoNewline -ForegroundColor Gray
            if ($event.FilePath -match "\.(exe|dll|bat|cmd|ps1|vbs|js|jar)$") {
                Write-Host "$($event.FilePath) [SUSPICIOUS TYPE]" -ForegroundColor Red
            } else {
                Write-Host "$($event.FilePath)" -ForegroundColor White
            }
        }
        
        if ($event.EventID -eq 4688 -and $event.Message -match "\| Command:\s*(.+)") {
            Write-Host "Command Line: " -NoNewline -ForegroundColor Gray
            Write-Host $matches[1].Trim() -ForegroundColor Cyan
        }
        
        Write-Host "Machine: " -NoNewline -ForegroundColor Gray
        Write-Host "$($event.Machine)" -ForegroundColor White
        
        if ($event.Reasons -and $event.Reasons.Count -gt 0) {
            Write-Host "Flags: " -ForegroundColor Red
            foreach ($reason in $event.Reasons) {
                Write-Host "  $reason" -ForegroundColor Red
            }
        }
        
        Write-Host "Details:" -ForegroundColor Gray
        if ($event.EventID -eq 4104) {
            if ($event.Message -match "Creating Scriptblock text \(1 of 1\):\s*([^\r\n]+)") {
                $command = $matches[1].Trim()
                Write-Host "  Command Executed: " -NoNewline -ForegroundColor Cyan
                Write-Host "$command" -ForegroundColor Yellow
            }
        }
        $messageLines = $event.Message -split "`n" | Select-Object -First 5
        foreach ($line in $messageLines) {
            if ($line.Trim() -and $line -notmatch "Creating Scriptblock text") {
                Write-Host "  $($line.Trim())" -ForegroundColor DarkGray
            }
        }
        
        Write-Host ""
        Write-Host $dashLine -ForegroundColor DarkGray
        Write-Host ""
    }
    
    Write-Host $separator -ForegroundColor Cyan
    Write-Host ""
}

function Get-SecurityEvents {
    param([datetime]$Since)
    
    $allEventIDs = @()
    foreach ($category in $Script:Config.EventIDs.Values) {
        if ($category -is [Array]) {
            $allEventIDs += $category
        } else {
            $allEventIDs += $category
        }
    }
    $allEventIDs = $allEventIDs | Sort-Object -Unique
    $events = @()
    
    if ($TestMode) {
        Write-Log "DEBUG: All Event IDs to query: $($allEventIDs -join ', ')" "INFO"
        Write-Log "DEBUG: Event 4660 in list: $($allEventIDs -contains 4660)" "INFO"
        Write-Log "DEBUG: Event 4698 in list: $($allEventIDs -contains 4698)" "INFO"
    }
    
    try {
        $fileEventIDs = @(4660, 4661, 4663, 4656, 4658, 4699, 4654, 4670)
        $registryEventIDs = @(4657)
        $otherEventIDs = $allEventIDs | Where-Object { $_ -notin ($fileEventIDs + $registryEventIDs) }
        
        $fileEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            ID = $fileEventIDs
            StartTime = $Since
        } -ErrorAction SilentlyContinue
        
        if ($fileEvents) {
            if ($TestMode) {
                Write-Log "DEBUG: Found $($fileEvents.Count) file events" "INFO"
                Write-Log "DEBUG: File Event IDs found: $($fileEvents.Id -join ', ')" "INFO"
            }
            foreach ($evt in $fileEvents) {
                $details = Get-EventDetails -Event $evt
                
                if ($details.EventID -eq 4663) {
                    $accessMatch = $details.Message -match "\| Access:\s*(.+)"
                    $accesses = if ($accessMatch) { $matches[1] } else { "" }
                    if ($accesses -match "DELETE|WriteData|ChangePermissions") {
                        $events += $details
                    }
                } else {
                    $events += $details
                }
            }
        }
        
        if ($registryEventIDs.Count -gt 0) {
            $registryEvents = Get-WinEvent -FilterHashtable @{
                LogName = "Security"
                ID = $registryEventIDs
                StartTime = $Since
            } -ErrorAction SilentlyContinue
            
            if ($registryEvents) {
                if ($TestMode) {
                    Write-Log "DEBUG: Found $($registryEvents.Count) registry events" "INFO"
                }
                foreach ($evt in $registryEvents) {
                    $details = Get-EventDetails -Event $evt
                    $events += $details
                }
            }
        }
        
        if ($otherEventIDs.Count -gt 0) {
            $otherEvents = Get-WinEvent -FilterHashtable @{
                LogName = "Security"
                ID = $otherEventIDs
                StartTime = $Since
            } -ErrorAction SilentlyContinue
            
            if ($otherEvents) {
                if ($TestMode) {
                    Write-Log "DEBUG: Found $($otherEvents.Count) other security events" "INFO"
                    Write-Log "DEBUG: Other Event IDs found: $($otherEvents.Id -join ', ')" "INFO"
                }
                foreach ($evt in $otherEvents) {
                    $details = Get-EventDetails -Event $evt
                    $events += $details
                }
            }
        }
        
        if ($TestMode -and $events.Count -eq 0) {
            Write-Log "DEBUG: No events returned, testing direct Event 4660 query..." "WARNING"
            $test4660 = Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4660; StartTime=$Since} -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($test4660) {
                Write-Log "DEBUG: Event 4660 EXISTS but query failed! Adding manually..." "ERROR"
                $details = Get-EventDetails -Event $test4660
                $events += $details
            }
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log "Error retrieving Security events: $errorMsg" "ERROR"
        if ($TestMode) {
            Write-Log "DEBUG: Exception type: $($_.Exception.GetType().Name)" "ERROR"
        }
    }
    
    return $events
}

function Get-TaskSchedulerEvents {
    param([datetime]$Since)
    
    $events = @()
    $taskEventIDs = $Script:Config.EventIDs.ScheduledTaskOperational
    
    try {
        $rawEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-TaskScheduler/Operational"
            ID = $taskEventIDs
            StartTime = $Since
        } -ErrorAction SilentlyContinue
        
        foreach ($evt in $rawEvents) {
            $details = @{
                Time = $evt.TimeCreated
                EventID = $evt.Id
                Level = $evt.LevelDisplayName
                Source = "TaskScheduler"
                Machine = $evt.MachineName
                Message = $evt.Message
                User = "N/A"
                IPAddress = "N/A"
                ProcessName = "TaskScheduler"
                FilePath = "N/A"
                RecordId = $evt.RecordId
            }
            
            if ($evt.Message -match "Task Name:\s*([^\r\n]+)") {
                $details.FilePath = $matches[1].Trim()
                $details.Message += " | Task: $($matches[1].Trim())"
            } elseif ($evt.Message -match "Task:\s*([^\r\n]+)") {
                $details.FilePath = $matches[1].Trim()
                $details.Message += " | Task: $($matches[1].Trim())"
            }
            
            $xml = [xml]$evt.ToXml()
            $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
            $ns.AddNamespace("ns", "http://schemas.microsoft.com/win/2004/08/events/event")
            
            $taskName = $xml.SelectSingleNode("//ns:Data[@Name='TaskName']", $ns)
            if ($taskName -and [string]::IsNullOrWhiteSpace($details.FilePath)) {
                $details.FilePath = $taskName.InnerText
                $details.Message += " | Task: $($taskName.InnerText)"
            }
            
            $events += $details
        }
    } catch {}
    
    return $events
}

function Get-ServiceEvents {
    param([datetime]$Since)
    
    $events = @()
    $serviceEventIDs = @(7034, 7035, 7036, 7040, 7045, 4697)
    
    try {
        $systemEvents = Get-WinEvent -FilterHashtable @{
            LogName = "System"
            ID = $serviceEventIDs
            StartTime = $Since
        } -ErrorAction SilentlyContinue
        
        foreach ($evt in $systemEvents) {
            $details = @{
                Time = $evt.TimeCreated
                EventID = $evt.Id
                Level = $evt.LevelDisplayName
                Source = "Service Control Manager"
                Machine = $evt.MachineName
                Message = $evt.Message
                User = "N/A"
                IPAddress = "N/A"
                ProcessName = "Services"
                FilePath = "N/A"
                RecordId = $evt.RecordId
            }
            
            $xml = [xml]$evt.ToXml()
            $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
            $ns.AddNamespace("ns", "http://schemas.microsoft.com/win/2004/08/events/event")
            
            $param1 = $xml.SelectSingleNode("//ns:Data[@Name='param1']", $ns)
            if ($param1) {
                $serviceName = $param1.InnerText
                $details.FilePath = $serviceName
                $details.Message += " | Service: $serviceName"
            }
            
            $events += $details
        }
        
        $securityServiceEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            ID = 4697
            StartTime = $Since
        } -ErrorAction SilentlyContinue
        
        foreach ($evt in $securityServiceEvents) {
            $details = Get-EventDetails -Event $evt
            $events += $details
        }
    } catch {}
    
    return $events
}

function Get-PowerShellEvents {
    param([datetime]$Since)
    
    $events = @()
    $psEventIDs = $Script:Config.EventIDs.PowerShell
    $scriptName = Split-Path -Leaf $MyInvocation.PSCommandPath
    
    try {
        $filterHashtable = @{
            LogName = "Microsoft-Windows-PowerShell/Operational"
            ID = $psEventIDs
            StartTime = $Since
        }
        
        $rawEvents = Get-WinEvent -FilterHashtable $filterHashtable -ErrorAction SilentlyContinue
        
        foreach ($evt in $rawEvents) {
            $message = $evt.Message
            
            if ($evt.Id -eq 4104) {
                if ($message -match "CCDC-Monitor|$scriptName") {
                    continue
                }
                $scriptBlockMatch = $message -match "Creating Scriptblock text \(1 of 1\):\s*([^\r\n]+)"
                if ($scriptBlockMatch) {
                    $command = $matches[1].Trim()
                    if ($command -match "^\s*prompt\s*$|^\s*cd\s+\S+\s*$|^\s*\$Host\s*$|Get-Location\s*$|Get-Command\s*$|Get-Help\s*$|^\s*dir\s*$|^\s*ls\s*$|^\s*pwd\s*$|^\s*clear\s*$|Set-StrictMode|ErrorCategory_Message|PSMessageDetails|OriginInfo|InnerException") {
                        continue
                    }
                }
            }
            
            if ($evt.Id -in @(4105, 4106)) {
                if ($message -match "CCDC-Monitor|$scriptName|prompt|Runspace|ScriptBlock ID|Completed invocation|Started invocation") {
                    continue
                }
            }
            
            $xml = [xml]$evt.ToXml()
            $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
            $ns.AddNamespace("ns", "http://schemas.microsoft.com/win/2004/08/events/event")
            
            $userId = $null
            $userSid = $xml.SelectSingleNode("//ns:UserId", $ns)
            if ($userSid) {
                $userId = Get-UserFromSID -SID $userSid.InnerText
            }
            
            if ([string]::IsNullOrWhiteSpace($userId) -or $userId -eq "N/A") {
                $userId = $env:USERNAME
            }
            
            $details = @{
                Time = $evt.TimeCreated
                EventID = $evt.Id
                Level = "Warning"
                Source = "PowerShell"
                Machine = $evt.MachineName
                Message = $message
                User = $userId
                IPAddress = "N/A"
                ProcessName = "PowerShell"
                FilePath = "N/A"
                RecordId = $evt.RecordId
            }
            $events += $details
        }
    } catch {}
    
    return $events
}

function Test-NoiseFilter {
    param([hashtable]$Event)
    
    if ($Event.User -in $Script:Config.NoiseFilters.Users) {
        foreach ($noisePath in $Script:Config.NoiseFilters.Paths) {
            if ($Event.FilePath -match $noisePath) {
                return $true
            }
            if ($Event.Message -match $noisePath) {
                return $true
            }
        }
    }
    
    return $false
}

function Test-SuspiciousActivity {
    param([hashtable]$Event)
    
    $isSuspicious = $false
    $reasons = @()
    
    if ($Event.ProcessName -in $Script:Config.SuspiciousProcesses) {
        $isSuspicious = $true
        $reasons += "Suspicious process: $($Event.ProcessName)"
    }
    
    if ($Event.FilePath -match "\.(exe|dll|bat|cmd|ps1|vbs|js|jar)$") {
        $isSuspicious = $true
        $reasons += "Suspicious file type: $($Event.FilePath)"
    }
    
    if ($Event.EventID -eq 4625) {
        $isSuspicious = $true
        $reasons += "Failed logon attempt"
    }
    
    if ($Event.User -match "Administrator|Admin" -and $Event.EventID -notin @(4104, 4105, 4106)) {
        if ($Event.EventID -in @(4624, 4648, 4672, 4720, 4722, 4724, 4726, 4728, 4732, 4733, 4756)) {
            $isSuspicious = $true
            $reasons += "Administrator account activity"
        }
    }
    
    if ($Event.IPAddress -ne "N/A" -and $Event.IPAddress -notmatch "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.") {
        $isSuspicious = $true
        $reasons += "External IP connection: $($Event.IPAddress)"
    }
    
    if ($Event.EventID -in $Script:Config.EventIDs.Account) {
        $isSuspicious = $true
        $reasons += "Account modification detected"
    }
    
    if ($Event.EventID -in @(4104, 4105, 4106)) {
        $message = $Event.Message
        if ($message -match "Invoke-Expression|IEX|DownloadString|WebClient|Net\.WebClient|Start-Process.*-WindowStyle.*Hidden|Invoke-WebRequest.*-UseBasicParsing|base64.*encoded|bypass.*execution|obfuscated") {
            $isSuspicious = $true
            $reasons += "Suspicious PowerShell command detected"
        }
    }
    
    return @{
        IsSuspicious = $isSuspicious
        Reasons = $reasons
    }
}

function Remove-DuplicateEvents {
    param([array]$Events)
    
    $uniqueEvents = @()
    $seen = @{}
    
    foreach ($evt in $Events) {
        $key = "$($evt.RecordId)-$($evt.EventID)-$($evt.Time.ToString('yyyyMMddHHmmss'))"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $uniqueEvents += $evt
        }
    }
    
    return $uniqueEvents
}

function Set-AuditPolicies {
    Write-Log "Setting up audit policies..." "INFO"
    
    $policies = @(
        @{Subcategory="Process Creation"; Include="Command Line"},
        @{Subcategory="File System"},
        @{Subcategory="Logon"},
        @{Subcategory="Logoff"},
        @{Subcategory="Account Lockout"},
        @{Subcategory="User Account Management"},
        @{Subcategory="Security Group Management"},
        @{Subcategory="Audit Policy Change"},
        @{Subcategory="Security System Extension"},
        @{Subcategory="Other System Events"},
        @{Subcategory="Other Object Access Events"}
    )
    
    $successCount = 0
    $failCount = 0
    
    foreach ($policy in $policies) {
        $result = auditpol /set /subcategory:"$($policy.Subcategory)" /success:enable /failure:enable 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "$($policy.Subcategory): Enabled" "SUCCESS"
            $successCount++
        } else {
            Write-Log "Failed to set $($policy.Subcategory): $result" "ERROR"
            $failCount++
        }
        
        if ($policy.Include -and $policy.Include -eq "Command Line") {
            $cmdLineRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            $cmdLineRegValue = "ProcessCreationIncludeCmdLine_Enabled"
            
            try {
                if (-not (Test-Path $cmdLineRegPath)) {
                    New-Item -Path $cmdLineRegPath -Force | Out-Null
                }
                Set-ItemProperty -Path $cmdLineRegPath -Name $cmdLineRegValue -Value 1 -Type DWord -Force
                Write-Log "$($policy.Subcategory) - $($policy.Include): Enabled (Registry)" "SUCCESS"
            } catch {
                Write-Log "Failed to set $($policy.Subcategory) include: $($_.Exception.Message)" "ERROR"
                $failCount++
            }
        }
    }
    
    Write-Log "Applied $successCount policies, $failCount failed" "INFO"
    
    Write-Log "Verifying Process Creation auditing..." "INFO"
    $verify = auditpol /get /subcategory:"Process Creation" 2>&1 | Out-String
    if ($verify -match "Success and Failure") {
        Write-Log "Process Creation auditing: ENABLED" "SUCCESS"
    } else {
        Write-Log "Process Creation auditing: NOT ENABLED" "ERROR"
    }
    
    Write-Log "Verifying Command Line auditing..." "INFO"
    $cmdLineRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $cmdLineRegValue = "ProcessCreationIncludeCmdLine_Enabled"
    
    try {
        $cmdLineReg = Get-ItemProperty -Path $cmdLineRegPath -Name $cmdLineRegValue -ErrorAction SilentlyContinue
        if ($cmdLineReg -and $cmdLineReg.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
            Write-Log "Command Line auditing: ENABLED (Registry)" "SUCCESS"
        } else {
            Write-Log "Command Line auditing: NOT ENABLED" "ERROR"
            Write-Log "May require reboot or gpupdate /force" "WARNING"
        }
    } catch {
        Write-Log "Command Line auditing: NOT ENABLED" "ERROR"
    }
}

function Enable-PowerShellLogging {
    Write-Log "Enabling PowerShell logging..." "INFO"
    
    try {
        $modulePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        if (-not (Test-Path $modulePath)) {
            New-Item -Path $modulePath -Force | Out-Null
        }
        Set-ItemProperty -Path $modulePath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
        Write-Log "Module logging enabled" "SUCCESS"
    } catch {
        Write-Log "Failed to enable module logging: $($_.Exception.Message)" "ERROR"
    }
    
    try {
        $scriptBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $scriptBlockPath)) {
            New-Item -Path $scriptBlockPath -Force | Out-Null
        }
        Set-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force
        Write-Log "Script block logging enabled" "SUCCESS"
    } catch {
        Write-Log "Failed to enable script block logging: $($_.Exception.Message)" "ERROR"
    }
    
    try {
        $transcriptionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        if (-not (Test-Path $transcriptionPath)) {
            New-Item -Path $transcriptionPath -Force | Out-Null
        }
        Set-ItemProperty -Path $transcriptionPath -Name "EnableTranscripting" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $transcriptionPath -Name "EnableInvocationHeader" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $transcriptionPath -Name "OutputDirectory" -Value "C:\PowerShell_Transcripts" -Type String -Force
        Write-Log "PowerShell transcription enabled" "SUCCESS"
    } catch {
        Write-Log "Failed to enable transcription: $($_.Exception.Message)" "WARNING"
    }
    
    try {
        $executionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
        if (-not (Test-Path $executionPath)) {
            New-Item -Path $executionPath -Force | Out-Null
        }
        Set-ItemProperty -Path $executionPath -Name "ExecutionPolicy" -Value "RemoteSigned" -Type String -Force -ErrorAction SilentlyContinue
    } catch {}
    
    Write-Log "PowerShell logging configuration complete" "SUCCESS"
    Write-Log "NOTE: You may need to restart PowerShell sessions for changes to take effect" "WARNING"
}

function Check-Events {
    param([datetime]$Since)
    
    $currentTime = Get-Date
    Write-Log "Checking for events since $Since" "INFO"
    
    $securityEvents = Get-SecurityEvents -Since $Since
    Write-Log "Found $($securityEvents.Count) security events" "INFO"
    
    $psEvents = Get-PowerShellEvents -Since $Since
    Write-Log "Found $($psEvents.Count) PowerShell events" "INFO"
    
    $taskEvents = Get-TaskSchedulerEvents -Since $Since
    Write-Log "Found $($taskEvents.Count) TaskScheduler events" "INFO"
    
    $serviceEvents = Get-ServiceEvents -Since $Since
    Write-Log "Found $($serviceEvents.Count) Service events" "INFO"
    
    $allEvents = @()
    if ($securityEvents) { $allEvents += $securityEvents }
    if ($psEvents) { $allEvents += $psEvents }
    if ($taskEvents) { $allEvents += $taskEvents }
    if ($serviceEvents) { $allEvents += $serviceEvents }
    
    Write-Log "Total events: $($allEvents.Count)" "INFO"
    
    if ($allEvents.Count -gt 0) {
        $allEvents = Remove-DuplicateEvents -Events $allEvents
        Write-Log "After deduplication: $($allEvents.Count) unique events" "INFO"
        
        Write-Log "Processing $($allEvents.Count) events..." "INFO"
        $suspiciousEvents = @()
        $importantEvents = @()
        
        foreach ($evt in $allEvents) {
            if (Test-NoiseFilter -Event $evt) {
                if ($TestMode) {
                    Write-Log "Filtered noise event: $($evt.EventID) by $($evt.User)" "INFO"
                }
                continue
            }
            
            if ($evt.EventID -eq 4688) {
                $importantEvents += $evt
            }
            
            if ($evt.EventID -eq 4625) {
                $importantEvents += $evt
            }
            
            if ($evt.EventID -in $Script:Config.EventIDs.Account) {
                $importantEvents += $evt
            }
            
            if ($evt.EventID -in @(4660, 4663, 4658, 4699, 4654, 4670)) {
                if ($evt.EventID -eq 4663) {
                    $accessMatch = $evt.Message -match "\| Access:\s*(.+)"
                    $accesses = if ($accessMatch) { $matches[1] } else { "" }
                    if ($accesses -match "DELETE|WriteData|ChangePermissions") {
                        $importantEvents += $evt
                    }
                } else {
                    $importantEvents += $evt
                }
            }
            
            if ($evt.EventID -in $Script:Config.EventIDs.ScheduledTask) {
                $importantEvents += $evt
            }
            
            if ($evt.EventID -in $Script:Config.EventIDs.ScheduledTaskOperational) {
                $importantEvents += $evt
            }
            
            if ($evt.EventID -eq 4657) {
                $importantEvents += $evt
            }
            
            if ($evt.EventID -in @(4697, 7034, 7035, 7036, 7040, 7045)) {
                $importantEvents += $evt
            }
            
            if ($evt.EventID -in @(4768, 4769, 4776, 4782)) {
                $importantEvents += $evt
            }
            
            if ($evt.EventID -eq 4104) {
                $msg = $evt.Message
                $scriptBlockMatch = $msg -match "Creating Scriptblock text \(1 of 1\):\s*([^\r\n]+)"
                if ($scriptBlockMatch) {
                    $command = $matches[1].Trim()
                    if ($command -match "^\s*prompt\s*$|^\s*cd\s+\S+\s*$|^\s*\$Host\s*$") {
                        continue
                    }
                }
                $importantEvents += $evt
            }
            
            $suspiciousCheck = Test-SuspiciousActivity -Event $evt
            if ($suspiciousCheck.IsSuspicious) {
                $evt.Reasons = $suspiciousCheck.Reasons
                $suspiciousEvents += $evt
            }
        }
        
        Write-Log "Important events: $($importantEvents.Count), Suspicious events: $($suspiciousEvents.Count)" "INFO"
        
        if ($importantEvents.Count -gt 0) {
            Write-Log "Displaying $($importantEvents.Count) important events" "INFO"
            Show-Alert -Events $importantEvents -AlertType "Security Events Detected"
        }
        
        if ($suspiciousEvents.Count -gt 0) {
            Write-Log "Displaying $($suspiciousEvents.Count) suspicious events" "INFO"
            Show-Alert -Events $suspiciousEvents -AlertType "SUSPICIOUS ACTIVITY ALERT"
            Write-Log "ALERT: $($suspiciousEvents.Count) suspicious events detected!" "CRITICAL"
        }
    }
    
    return $currentTime
}

function Show-AuditStatus {
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "AUDIT POLICY STATUS" -ForegroundColor Cyan
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $policies = @(
        @{Name="Process Creation"; Subcategory="Process Creation"},
        @{Name="Command Line"; Subcategory="Process Creation"; Type="Registry"},
        @{Name="File System"; Subcategory="File System"},
        @{Name="Logon"; Subcategory="Logon"},
        @{Name="Other System Events"; Subcategory="Other System Events"},
        @{Name="Other Object Access Events"; Subcategory="Other Object Access Events"}
    )
    
    foreach ($policy in $policies) {
        if ($policy.Type -eq "Registry") {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            $regValue = "ProcessCreationIncludeCmdLine_Enabled"
            try {
                $reg = Get-ItemProperty -Path $regPath -Name $regValue -ErrorAction SilentlyContinue
                if ($reg -and $reg.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
                    Write-Host "[OK] $($policy.Name): ENABLED" -ForegroundColor Green
                } else {
                    Write-Host "[X] $($policy.Name): DISABLED" -ForegroundColor Red
                }
            } catch {
                Write-Host "[X] $($policy.Name): DISABLED" -ForegroundColor Red
            }
        } else {
            $status = auditpol /get /subcategory:"$($policy.Subcategory)" 2>&1 | Out-String
            if ($status -match "Success and Failure") {
                Write-Host "[OK] $($policy.Name): ENABLED" -ForegroundColor Green
            } else {
                Write-Host "[X] $($policy.Name): DISABLED" -ForegroundColor Red
            }
        }
    }
    
    Write-Host ""
    Write-Host "Press any key to continue..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Enable-IndividualAudit {
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "ENABLE INDIVIDUAL AUDIT POLICY" -ForegroundColor Cyan
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Process Creation" -ForegroundColor Yellow
    Write-Host "2. Command Line" -ForegroundColor Yellow
    Write-Host "3. File System" -ForegroundColor Yellow
    Write-Host "4. Logon" -ForegroundColor Yellow
    Write-Host "5. Other System Events (Scheduled Tasks)" -ForegroundColor Yellow
    Write-Host "6. Other Object Access Events (Required for Task Events)" -ForegroundColor Yellow
    Write-Host "7. Enable All" -ForegroundColor Yellow
    Write-Host "8. Back" -ForegroundColor Yellow
    Write-Host ""
    $choice = Read-Host "Select option (1-8)"
    
    switch ($choice) {
        "1" {
            auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
            Write-Host "Process Creation auditing enabled" -ForegroundColor Green
        }
        "2" {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
            $regValue = "ProcessCreationIncludeCmdLine_Enabled"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name $regValue -Value 1 -Type DWord -Force
            Write-Host "Command Line auditing enabled" -ForegroundColor Green
        }
        "3" {
            auditpol /set /subcategory:"File System" /success:enable /failure:enable
            Write-Host "File System auditing enabled" -ForegroundColor Green
        }
        "4" {
            auditpol /set /subcategory:"Logon" /success:enable /failure:enable
            Write-Host "Logon auditing enabled" -ForegroundColor Green
        }
        "5" {
            auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
            Write-Host "Other System Events auditing enabled" -ForegroundColor Green
        }
        "6" {
            auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
            Write-Host "Other Object Access Events auditing enabled" -ForegroundColor Green
            Write-Host "This enables Event 4698 for scheduled tasks" -ForegroundColor Yellow
        }
        "7" {
            Set-AuditPolicies
            Write-Host "All audit policies enabled" -ForegroundColor Green
        }
    }
    
    if ($choice -ne "8") {
        Write-Host ""
        Write-Host "Press any key to continue..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

function List-SACLs {
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "FOLDERS WITH SACLs CONFIGURED" -ForegroundColor Cyan
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $commonPaths = @(
        "C:\Windows\System32\drivers\etc",
        "C:\Windows\System32\Tasks",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\inetpub",
        "C:\Windows\Temp"
    )
    
    $foundSACLs = @()
    
    foreach ($path in $commonPaths) {
        if ($path -match "\*") {
            $resolvedPaths = Resolve-Path $path -ErrorAction SilentlyContinue
            if ($resolvedPaths) {
                foreach ($resolved in $resolvedPaths) {
                    $path = $resolved.Path
                    if (Test-Path $path) {
                        try {
                            $acl = Get-Acl $path -Audit -ErrorAction SilentlyContinue
                            if ($acl -and $acl.Audit) {
                                $auditRules = $acl.Audit | Where-Object { $_.AuditFlags -ne "None" }
                                if ($auditRules) {
                                    $foundSACLs += @{
                                        Path = $path
                                        Rules = $auditRules
                                    }
                                    Write-Host "[OK] $path" -ForegroundColor Green
                                    foreach ($rule in $auditRules) {
                                        Write-Host "  - Identity: $($rule.IdentityReference)" -ForegroundColor Gray
                                        Write-Host "    Rights: $($rule.FileSystemRights)" -ForegroundColor Gray
                                        Write-Host "    AuditFlags: $($rule.AuditFlags)" -ForegroundColor Gray
                                    }
                                    Write-Host ""
                                }
                            }
                        } catch {}
                    }
                }
            }
        } else {
            if (Test-Path $path) {
                try {
                    $acl = Get-Acl $path -Audit -ErrorAction SilentlyContinue
                    if ($acl -and $acl.Audit) {
                        $auditRules = $acl.Audit | Where-Object { $_.AuditFlags -ne "None" }
                        if ($auditRules) {
                            $foundSACLs += @{
                                Path = $path
                                Rules = $auditRules
                            }
                            Write-Host "[OK] $path" -ForegroundColor Green
                            foreach ($rule in $auditRules) {
                                Write-Host "  - Identity: $($rule.IdentityReference)" -ForegroundColor Gray
                                Write-Host "    Rights: $($rule.FileSystemRights)" -ForegroundColor Gray
                                Write-Host "    AuditFlags: $($rule.AuditFlags)" -ForegroundColor Gray
                            }
                            Write-Host ""
                        }
                    }
                } catch {}
            }
        }
    }
    
    if ($foundSACLs.Count -eq 0) {
        Write-Host "[X] No SACLs found on common system paths" -ForegroundColor Red
        Write-Host ""
        Write-Host "RECOMMENDED: Do NOT add SACLs to entire System32!" -ForegroundColor Yellow
        Write-Host "Instead, target specific folders:" -ForegroundColor Yellow
        Write-Host "  - C:\Windows\System32\drivers\etc (hosts file)" -ForegroundColor Gray
        Write-Host "  - C:\Windows\System32\Tasks (scheduled tasks)" -ForegroundColor Gray
        Write-Host "  - Startup folders" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Use option 5 to add SACLs to specific folders" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Press any key to continue..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Add-SACL {
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "ADD SACL TO FOLDER" -ForegroundColor Cyan
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "WARNING: Do NOT add SACLs to entire System32!" -ForegroundColor Yellow
    Write-Host "This will generate massive noise from SYSTEM/LOCAL SERVICE" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Recommended paths:" -ForegroundColor Green
    Write-Host "  - C:\Windows\System32\drivers\etc" -ForegroundColor Gray
    Write-Host "  - C:\Windows\System32\Tasks" -ForegroundColor Gray
    Write-Host "  - C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Enter folder path to add SACL (or press Enter for default: C:\Windows\System32\Tasks)" -ForegroundColor Yellow
    $folderPath = Read-Host "Folder path"
    
    if ([string]::IsNullOrWhiteSpace($folderPath)) {
        $folderPath = "C:\Windows\System32\Tasks"
    }
    
    if (-not (Test-Path $folderPath)) {
        Write-Host "ERROR: Folder does not exist: $folderPath" -ForegroundColor Red
        Write-Host ""
        Write-Host "Press any key to continue..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
    Write-Host ""
    Write-Host "Adding SACL to: $folderPath" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $acl = Get-Acl $folderPath
        
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone",
            "Delete, WriteData, CreateFiles, WriteAttributes, ChangePermissions, TakeOwnership",
            "ContainerInherit,ObjectInherit",
            "None",
            "Success, Failure"
        )
        
        $acl.SetAuditRule($auditRule)
        Set-Acl $folderPath $acl
        
        Write-Host "[OK] SACL added successfully to $folderPath" -ForegroundColor Green
        Write-Host ""
        Write-Host "The following operations will now be logged:" -ForegroundColor Yellow
        Write-Host "  - File deletion (Event 4660, 4663 with DELETE)" -ForegroundColor Gray
        Write-Host "  - File creation (Event 4663 with WriteData)" -ForegroundColor Gray
        Write-Host "  - File modification (Event 4663)" -ForegroundColor Gray
        Write-Host "  - Permission changes (Event 4654, 4670)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Events 4660, 4663, 4654, 4670 will now be generated for this folder" -ForegroundColor Green
        
    } catch {
        Write-Host "[X] Failed to add SACL: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Make sure you have Administrator privileges" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Press any key to continue..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Change-LogPath {
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "CHANGE LOG FILE PATH" -ForegroundColor Cyan
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Current log file: $Script:LogFilePath" -ForegroundColor Yellow
    Write-Host ""
    $defaultLogPath = ".\SecurityMonitor_$(Get-Date -Format 'yyyyMMdd').log"
    $newLogPath = Read-Host "Enter new log file path (or press Enter for default: $defaultLogPath)"
    
    if ([string]::IsNullOrWhiteSpace($newLogPath)) {
        $newLogPath = $defaultLogPath
    }
    
    $logDirectory = Split-Path -Path $newLogPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($logDirectory) -and -not (Test-Path $logDirectory)) {
        try {
            New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
            Write-Host "[OK] Created log directory: $logDirectory" -ForegroundColor Green
        } catch {
            Write-Host "[X] Warning: Could not create log directory: $logDirectory" -ForegroundColor Yellow
            Write-Host "Logs will only be displayed on screen." -ForegroundColor Yellow
            $newLogPath = ""
        }
    }
    
    if (-not [string]::IsNullOrWhiteSpace($newLogPath)) {
        $Script:LogFilePath = $newLogPath
        Write-Host "[OK] Log file path changed to: $Script:LogFilePath" -ForegroundColor Green
        Write-Log "Log file path changed to: $Script:LogFilePath" "INFO"
    } else {
        Write-Host "[X] Invalid log path. Keeping current path." -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "Press any key to continue..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Start-Monitoring {
    Write-Log "Starting Security Monitoring on $($Script:Config.SystemName)" "INFO"
    Write-Log "Monitoring interval: $CheckInterval seconds" "INFO"
    Write-Log "Lookback window: $($Script:Config.LookbackMinutes) minutes" "INFO"
    
    $lastCheck = (Get-Date).AddMinutes(-$Script:Config.LookbackMinutes)
    $nextAutoCheck = (Get-Date).AddSeconds($CheckInterval)
    $lastMenuDisplay = (Get-Date).AddSeconds(-10)
    
    while ($true) {
        if ((Get-Date) -ge $nextAutoCheck) {
            Write-Host ""
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "AUTOMATIC CHECK" -ForegroundColor Cyan
            Write-Host "===================================================================" -ForegroundColor Cyan
            $lastCheck = Check-Events -Since $lastCheck
            $nextAutoCheck = (Get-Date).AddSeconds($CheckInterval)
            $lastMenuDisplay = Get-Date
        }
        
        if ((Get-Date) -ge $lastMenuDisplay.AddSeconds(5)) {
            Write-Host ""
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "MONITORING MENU" -ForegroundColor Cyan
            Write-Host "===================================================================" -ForegroundColor Cyan
            Write-Host "ENTER - Force check for alerts now" -ForegroundColor Yellow
            Write-Host "1 - Verify audit policies" -ForegroundColor Yellow
            Write-Host "2 - List all audit policy status" -ForegroundColor Yellow
            Write-Host "3 - Enable individual audit policy" -ForegroundColor Yellow
            Write-Host "4 - List folders with SACLs" -ForegroundColor Yellow
            Write-Host "5 - Add SACL to folder" -ForegroundColor Yellow
            Write-Host "6 - Change log file path" -ForegroundColor Yellow
            Write-Host "Q - Quit" -ForegroundColor Yellow
            Write-Host "===================================================================" -ForegroundColor Cyan
            $nextCheckTime = $nextAutoCheck.ToString("HH:mm:ss")
            Write-Host "Next automatic check at: $nextCheckTime" -ForegroundColor Gray
            Write-Host "Current log file: $Script:LogFilePath" -ForegroundColor Gray
            Write-Host ""
            $lastMenuDisplay = Get-Date
        }
        
        if ($Host.UI.RawUI.KeyAvailable) {
            $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            
            if ($key.Character -eq 'q' -or $key.Character -eq 'Q') {
                Write-Host ""
                Write-Log "Stopping monitor..." "INFO"
                break
            }
            elseif ($key.VirtualKeyCode -eq 13 -or $key.Character -eq "`r") {
                Write-Host ""
                Write-Host "===================================================================" -ForegroundColor Cyan
                Write-Host "FORCING IMMEDIATE CHECK" -ForegroundColor Cyan
                Write-Host "===================================================================" -ForegroundColor Cyan
                $lastCheck = Check-Events -Since $lastCheck
                $nextAutoCheck = (Get-Date).AddSeconds($CheckInterval)
                $lastMenuDisplay = Get-Date
            }
            elseif ($key.Character -eq '1') {
                Write-Host ""
                Write-Host "Running audit verification..." -ForegroundColor Yellow
                if (Test-Path $Script:VerifyScriptPath) {
                    & $Script:VerifyScriptPath
                } else {
                    Write-Host "[X] Verify script not found at: $Script:VerifyScriptPath" -ForegroundColor Red
                    Write-Host "Please update the verify script path in the menu or at startup." -ForegroundColor Yellow
                }
                $lastMenuDisplay = Get-Date
            }
            elseif ($key.Character -eq '2') {
                Show-AuditStatus
                $lastMenuDisplay = Get-Date
            }
            elseif ($key.Character -eq '3') {
                Enable-IndividualAudit
                $lastMenuDisplay = Get-Date
            }
            elseif ($key.Character -eq '4') {
                List-SACLs
                $lastMenuDisplay = Get-Date
            }
            elseif ($key.Character -eq '5') {
                Add-SACL
                $lastMenuDisplay = Get-Date
            }
            elseif ($key.Character -eq '6') {
                Change-LogPath
                $lastMenuDisplay = Get-Date
            }
        }
        
        Start-Sleep -Milliseconds 100
    }
}

if ($SetupAudit) {
    Write-Log "Setting up audit policies and logging..." "INFO"
    Set-AuditPolicies
    Enable-PowerShellLogging
    
    Write-Log "Verifying settings..." "INFO"
    $moduleLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
    $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    
    if ($moduleLogging.EnableModuleLogging -eq 1) {
        Write-Log "Module Logging: ENABLED" "SUCCESS"
    } else {
        Write-Log "Module Logging: NOT ENABLED - Check permissions" "ERROR"
    }
    
    if ($scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
        Write-Log "Script Block Logging: ENABLED" "SUCCESS"
    } else {
        Write-Log "Script Block Logging: NOT ENABLED - Check permissions" "ERROR"
    }
    
    Write-Log "Setup complete! Restart PowerShell sessions for changes to take effect." "SUCCESS"
    Write-Log "Then restart the script to begin monitoring." "INFO"
    exit 0
}

Clear-Host
Write-Host "SECURITY MONITORING SYSTEM" -ForegroundColor Cyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script should be run as Administrator for full functionality"
}

$auditStatus = auditpol /get /subcategory:"Process Creation" 2>&1 | Out-String
if ($auditStatus -notmatch "Success and Failure") {
    Write-Host "WARNING: Process Creation auditing is NOT enabled!" -ForegroundColor Red
    Write-Host "This means Event ID 4688 (process creation) will NOT be logged." -ForegroundColor Red
    Write-Host "Run: .\CCDC-Monitor.ps1 -SetupAudit" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To test if events are being generated, run:" -ForegroundColor Yellow
    Write-Host "  Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} -MaxEvents 5" -ForegroundColor Gray
    Write-Host ""
}

Write-Log "Security Monitor initialized" "INFO"
Write-Log "System: $($Script:Config.SystemName)" "INFO"
Write-Log "Domain: $($Script:Config.Domain)" "INFO"

if ($Script:LogFilePath -and -not [string]::IsNullOrWhiteSpace($Script:LogFilePath)) {
    Write-Log "Logging to file: $Script:LogFilePath" "INFO"
} else {
    Write-Log "Logging to file: DISABLED (logs will only be displayed on screen)" "WARNING"
}

Start-Monitoring
