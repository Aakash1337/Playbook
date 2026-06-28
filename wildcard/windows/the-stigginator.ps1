# THE STIGGINATOR authored by @Lfgberg - https://lfgberg.org
# This is a wrapper to automatically apply everything from Microsoft's PowerSTIG that is applicable to the target server
# https://github.com/Microsoft/PowerStig

# TODO: Implement stigs for windowsdnsserver, DotnetFramework, office, sqlserver, oraclejre?

# CONFIGURE THESE (ALWAYS) - They can be found using `Get-Stig -ListAvailable`
$OsVersion = "2022" # Windows Version ex 11, 2022, 2002R2
$OsRole = "DC" # ['DC', 'MS']
$InternetExplorerVersion = "11"
$IISVersion = "10.0"
$logPath = "C:\Logs"
$transcriptPath = Join-Path $logPath "the-stigginator.log"

# CONFIGURE THESE (SOMETIMES) - They can be found using `Get-Stig -ListAvailable`
# STIG Versions
$WinServStigVersion = "2.3"
$WinClientStigVersion = "2.2"
$WinDefenderFirewallStigVersion = "2.2"
$WinDefenderStigVersion = "2.4"
$FireFoxStigVersion = "6.5"
$EdgeStigVersion = "2.2"
$ExplorerStigVersion = "2.5"
$IISServerStigVersion = "3.1"
$IISSiteStigVersion = "2.9"
$ChromeStigVersion = "2.9"
$AcrobatStigVersion = "2.1"

# Variables
$OutputPath = "C:\STIGConfig"     # Directory for the configuration
$LogPath = "C:\Logs"
$ComputerName = "localhost" # Localhost by default

# Create logging directory & start transcript
New-Item -ItemType Directory -Path $logPath
Start-Transcript -Path $transcriptPath

Install-Module -Name PowerSTIG -Force -AllowClobber -Confirm
# Install required modules if missing
(Get-Module PowerSTIG -ListAvailable).RequiredModules | ForEach-Object {
    if (-not (Get-Module -ListAvailable -Name $_.Name)) {
        Write-Host "Installing required module: $($_.Name)"
        Install-Module -Name $_.Name -Force
    }
}
Set-Item -Path WSMan:\localhost\MaxEnvelopeSizekb -Value 8192

# List of applications to detect with their registry keys
$Applications = @(
    @{ Name = "Edge";         Pattern = "*Edge*" },
    @{ Name = "Internet Explorer"; RegistryKeys = @(
            'HKLM:\Software\Microsoft\Internet Explorer',
            'HKLM:\Software\WOW6432Node\Microsoft\Internet Explorer'
        )},
    @{ Name = "IIS Server"; RegistryKeys = @('HKLM:\SOFTWARE\Microsoft\InetStp', 'HKLM:\SOFTWARE\Microsoft\Inetmgr') },
    @{ Name = "Chrome";   Pattern = "*Chrome*" },
    @{ Name = "Acrobat";   Pattern = "*Adobe Acrobat*" },
    @{ Name = "Firefox";         Pattern = "*Firefox*" }
)

# Function to detect application installations
function Detect-Application {
    param ($App)
    
    if ($App.RegistryKeys) {
        # Check registry keys directly
        $IsInstalled = $false
        $Version = $null

        foreach ($Key in $App.RegistryKeys) {
            if (Test-Path $Key) {
                $Version = (Get-ItemProperty $Key -ErrorAction SilentlyContinue).Version
                $IsInstalled = $true
                break
            }
        }

        [PSCustomObject]@{
            Name        = $App.Name
            Path        = "Registry: $Key"
            Version     = $Version
            IsInstalled = $IsInstalled
        }

    } else {
        # Check regular Uninstall entries
        $Path = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', `
                                    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
                 | Where-Object { $_.DisplayName -like $App.Pattern } `
                 | Select-Object -ExpandProperty InstallLocation) -join ''
    
        $IsInstalled = $Path -and (Test-Path $Path)
    
        [PSCustomObject]@{
            Name        = $App.Name
            Path        = $Path
            IsInstalled = $IsInstalled
        }
    }
}

# Detect all applications and display results
$Results = $Applications | ForEach-Object { Detect-Application $_ }

# Dynamically create variables based on application names
$Results | ForEach-Object {
    $VarName = $_.Name -replace '\s', ''   # Remove spaces in the variable name (e.g., "MS Edge" → "MSEdge")
    New-Variable -Name $VarName -Value $_ -Force
}

# Display detected applications
$Results | ForEach-Object {
    if ($_.IsInstalled) {
        Write-Host "$($_.Name) detected at: $($_.Path)"
    } else {
        Write-Host "$($_.Name) not detected. Skipping."
    }
}

# Detect if the machine is running a Windows Server version
$IsServer = (Get-CimInstance Win32_OperatingSystem).ProductType -in 2, 3

if ($IsServer) {
    Write-Host "Windows Server detected."
} else {
    Write-Host "Windows Client detected."
}

if ($IISServer.IsInstalled){
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools
    Import-Module WebAdministration
    Get-Website
}

# DSC Configuration for Multiple STIGs
Configuration MultiSTIG
{
    Import-DscResource -ModuleName PowerSTIG

    Node $ComputerName
    {
        # Windows Server (If Server)
        if ($IsServer) {
            WindowsServer BaseLine
            {
                OsVersion    = $OsVersion
                StigVersion  = $WinServStigVersion
                OsRole = $OsRole
            }
        } else {
            # Windows Client (If not server)
            WindowsClient BaseLine
            {
                OsVersion = $OsVersion
                StigVersion = $WinClientStigVersion
            }
        }

        # Windows Firewall
        WindowsFirewall EnterpriseFirewallPolicy
        {
            StigVersion = $WinDefenderFirewallStigVersion
        }

        # Windows Defender
        WindowsDefender DefenderSettings
        {
            StigVersion = $WinDefenderStigVersion
        }

        # Firefox (only if installed)
        if ($Firefox.IsInstalled) {
            FireFox BaseLine
            {
                StigVersion      = $FireFoxStigVersion
                InstallDirectory = $Firefox.Path
            }
        }

        # Edge (only if installed)
        if ($Edge.IsInstalled) {
            Edge BaseLine
            {
                StigVersion      = $EdgeStigVersion
            }
        }

        # IE (only if installed)
        if ($InternetExplorer.IsInstalled) {
            InternetExplorer BaseLine
            {
                StigVersion      = $ExplorerStigVersion
                BrowserVersion = $InternetExplorerVersion
            }
        }

        # Chrome (only if installed)
        if ($Chrome.IsInstalled) {
            Chrome BaseLine
            {
                StigVersion      = $ChromeStigVersion
            }
        }

        # Acrobat (only if installed)
        if ($Acrobat.IsInstalled) {
            Adobe BaseLine
            {
                StigVersion      = $AcrobatStigVersion
                AdobeApp = "AcrobatReader"
            }
        }

        # IIS (only if installed)
        if ($IISServer.IsInstalled) {

            # Fetch all IIS sites
            $IISSites = Get-WebSite

            # Apply STIG for IIS Server
            IisServer BaseLine {
                StigVersion = $IISServerStigVersion
                IisVersion  = $IISVersion
                LogPath     = $LogPath
            }

            # Loop through all IIS Sites and apply STIG
            foreach ($Site in $IISSites) {
                IisSite $Site.Name {
                    StigVersion  = $IISSiteStigVersion
                    IisVersion   = $IISVersion
                    WebSiteName  = $Site.Name
                    WebAppPool   = $Site.ApplicationPool
                }
            }
        }
    }
}

# Generate and Apply the Configuration
MultiSTIG -OutputPath $OutputPath

# Apply the DSC configuration locally
Start-DscConfiguration -Path $OutputPath -Wait -Verbose -Force