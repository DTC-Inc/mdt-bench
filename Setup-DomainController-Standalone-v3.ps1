<#
.SYNOPSIS
    Complete Standalone Domain Controller Setup Script - MSP RMM Template Version
.DESCRIPTION
    Single-file setup script for Domain Controller servers following MSP Script Library standards.
    Fully non-interactive when running from RMM ($RMM=1).
.NOTES
    Author: DTC Inc
    Version: 3.0 MSP Template
    Date: 2025-12-19
#>

## PLEASE COMMENT YOUR VARIABLES DIRECTLY BELOW HERE IF YOU'RE RUNNING FROM A RMM
## THIS IS HOW WE EASILY LET PEOPLE KNOW WHAT VARIABLES NEED SET IN THE RMM
## $RMM = 1                          # Set to 1 when running from RMM (REQUIRED)
## $ServerSequence = "01"            # Server sequence number 01-99 (REQUIRED)
## $SkipWindowsUpdate = $false       # Skip Windows Updates
## $SkipNetworkTeaming = $false     # Skip network team configuration
## $InstallADDS = $false             # Install AD DS role
## $DomainName = "corp.local"       # Domain name for new forest
## $NetBIOSName = "CORP"            # NetBIOS domain name
## $InstallDHCP = $false            # Install DHCP Server role
## $CompanyName = "DTC"             # Company name for branding

#Requires -RunAsAdministrator
#Requires -Version 5.1

# ============================================================================
# SECTION 1: RMM VARIABLE DECLARATION AND INPUT HANDLING
# ============================================================================

$ScriptLogName = "DomainController-Setup-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"
$ServerRole = "DC"  # Domain Controller role code

# Default configuration values
$Config = @{
    ServerSequence = ""
    SkipWindowsUpdate = $false
    SkipNetworkTeaming = $false
    InstallADDS = $false
    DomainName = "corp.local"
    NetBIOSName = "CORP"
    InstallDHCP = $false
    CompanyName = "DTC"
    NonInteractive = $false
}

# Function to validate server sequence
function Test-ServerSequence {
    param([string]$Sequence)
    return $Sequence -match '^\d{1,2}$' -and [int]$Sequence -ge 1 -and [int]$Sequence -le 99
}

if ($RMM -ne 1) {
    # INTERACTIVE MODE - Get input from user
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Domain Controller Setup - Interactive Mode" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    # Server sequence (REQUIRED)
    $ValidInput = 0
    while ($ValidInput -ne 1) {
        Write-Host "`nServer Naming Configuration" -ForegroundColor Yellow
        Write-Host "Server will be named: ${ServerRole}XX (e.g., DC01, DC02)" -ForegroundColor Gray
        $sequence = Read-Host "Enter the sequence number for this server (1-99)"

        if (Test-ServerSequence $sequence) {
            $Config.ServerSequence = "{0:d2}" -f [int]$sequence
            $ValidInput = 1
        } else {
            Write-Host "Invalid input. Please enter a number between 1 and 99." -ForegroundColor Red
        }
    }

    # Optional configurations
    $Config.CompanyName = Read-Host "Enter company name (default: DTC)"
    if ([string]::IsNullOrEmpty($Config.CompanyName)) { $Config.CompanyName = "DTC" }

    $skipUpdate = Read-Host "Skip Windows Updates? (y/n, default: n)"
    $Config.SkipWindowsUpdate = ($skipUpdate -eq 'y')

    $skipTeaming = Read-Host "Skip network teaming? (y/n, default: n)"
    $Config.SkipNetworkTeaming = ($skipTeaming -eq 'y')

    $installADDS = Read-Host "Install Active Directory Domain Services? (y/n, default: n)"
    $Config.InstallADDS = ($installADDS -eq 'y')

    if ($Config.InstallADDS) {
        $domain = Read-Host "Enter domain name (default: corp.local)"
        if (-not [string]::IsNullOrEmpty($domain)) { $Config.DomainName = $domain }

        $netbios = Read-Host "Enter NetBIOS name (default: CORP)"
        if (-not [string]::IsNullOrEmpty($netbios)) { $Config.NetBIOSName = $netbios }

        $installDHCP = Read-Host "Install DHCP Server? (y/n, default: n)"
        $Config.InstallDHCP = ($installDHCP -eq 'y')
    }

    # Set log path for interactive mode
    $LogPath = "$ENV:WINDIR\logs\$ScriptLogName"

} else {
    # RMM MODE - Use pre-set variables, no interaction allowed
    Write-Host "Running in RMM mode - Non-interactive execution" -ForegroundColor Green
    $Config.NonInteractive = $true

    # Get variables from RMM environment or use defaults
    if ($null -eq $ServerSequence) {
        # Try environment variable as fallback
        $ServerSequence = $env:MDT_SERVER_SEQUENCE
        if ([string]::IsNullOrEmpty($ServerSequence)) {
            Write-Host "ERROR: ServerSequence is required when running from RMM!" -ForegroundColor Red
            Write-Host "Set either `$ServerSequence or MDT_SERVER_SEQUENCE environment variable" -ForegroundColor Red
            exit 1
        }
    }

    # Validate and format server sequence
    if (Test-ServerSequence $ServerSequence) {
        $Config.ServerSequence = "{0:d2}" -f [int]$ServerSequence
    } else {
        Write-Host "ERROR: Invalid ServerSequence value: $ServerSequence" -ForegroundColor Red
        exit 1
    }

    # Map RMM variables to config (use defaults if not set)
    $Config.SkipWindowsUpdate = if ($null -ne $SkipWindowsUpdate) { $SkipWindowsUpdate } else { $false }
    $Config.SkipNetworkTeaming = if ($null -ne $SkipNetworkTeaming) { $SkipNetworkTeaming } else { $false }
    $Config.InstallADDS = if ($null -ne $InstallADDS) { $InstallADDS } else { $false }
    $Config.DomainName = if ($null -ne $DomainName) { $DomainName } else { "corp.local" }
    $Config.NetBIOSName = if ($null -ne $NetBIOSName) { $NetBIOSName } else { "CORP" }
    $Config.InstallDHCP = if ($null -ne $InstallDHCP) { $InstallDHCP } else { $false }
    $Config.CompanyName = if ($null -ne $CompanyName) { $CompanyName } else { "DTC" }

    # Set log path for RMM mode
    if ($null -ne $RMMScriptPath) {
        $LogPath = "$RMMScriptPath\logs\$ScriptLogName"
        if (!(Test-Path "$RMMScriptPath\logs")) {
            New-Item -ItemType Directory -Path "$RMMScriptPath\logs" -Force | Out-Null
        }
    } else {
        $LogPath = "$ENV:WINDIR\logs\$ScriptLogName"
    }
}

# Ensure log directory exists
$LogDir = Split-Path $LogPath -Parent
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Build the new computer name
$NewComputerName = "${ServerRole}$($Config.ServerSequence)"

# ============================================================================
# SECTION 2: HELPER FUNCTIONS
# ============================================================================

# Enhanced logging function
function Write-ScriptLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"

    $color = switch($Level) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        "Success" { "Green" }
        default { "White" }
    }

    Write-Host $LogMessage -ForegroundColor $color
}

# ============================================================================
# SECTION 3: MAIN SCRIPT LOGIC
# ============================================================================

Start-Transcript -Path $LogPath

try {
    Write-ScriptLog "========================================" -Level "Info"
    Write-ScriptLog "$($Config.CompanyName) - Domain Controller Setup Script (v3.0)" -Level "Info"
    Write-ScriptLog "========================================" -Level "Info"
    Write-ScriptLog "" -Level "Info"
    Write-ScriptLog "Configuration Settings:" -Level "Info"
    Write-ScriptLog "  RMM Mode: $($RMM -eq 1)" -Level "Info"
    Write-ScriptLog "  Company Name: $($Config.CompanyName)" -Level "Info"
    Write-ScriptLog "  New Computer Name: $NewComputerName" -Level "Info"
    Write-ScriptLog "  Current Computer Name: $env:COMPUTERNAME" -Level "Info"
    Write-ScriptLog "  Skip Windows Update: $($Config.SkipWindowsUpdate)" -Level "Info"
    Write-ScriptLog "  Skip Network Teaming: $($Config.SkipNetworkTeaming)" -Level "Info"
    Write-ScriptLog "  Install AD DS: $($Config.InstallADDS)" -Level "Info"
    Write-ScriptLog "  Domain Name: $($Config.DomainName)" -Level "Info"
    Write-ScriptLog "  NetBIOS Name: $($Config.NetBIOSName)" -Level "Info"
    Write-ScriptLog "  Install DHCP: $($Config.InstallDHCP)" -Level "Info"
    Write-ScriptLog "  Log Path: $LogPath" -Level "Info"
    Write-ScriptLog "" -Level "Info"

    #region Step 0: Rename Computer
    Write-ScriptLog "Step 0: Computer Naming Configuration..." -Level "Info"

    if ($env:COMPUTERNAME -ne $NewComputerName) {
        Write-ScriptLog "Renaming computer from '$env:COMPUTERNAME' to '$NewComputerName'..." -Level "Info"

        try {
            Rename-Computer -NewName $NewComputerName -Force -ErrorAction Stop
            Write-ScriptLog "Computer renamed successfully to '$NewComputerName'" -Level "Success"
            Write-ScriptLog "Note: Restart required for name change to take effect" -Level "Warning"
            $Global:RestartRequired = $true
        } catch {
            Write-ScriptLog "Failed to rename computer: $_" -Level "Error"
            if (-not $Config.NonInteractive) {
                $continue = Read-Host "Failed to rename computer. Continue anyway? (y/n)"
                if ($continue -ne 'y') {
                    throw "Setup cancelled due to computer rename failure"
                }
            }
        }
    } else {
        Write-ScriptLog "Computer name already set to '$NewComputerName'" -Level "Info"
        $Global:RestartRequired = $false
    }
    #endregion

    #region Step 1: Storage Configuration
    Write-ScriptLog "Step 1: Configuring Storage..." -Level "Info"

    try {
        # Check for dedicated boot disk scenario
        $bootDisk = Get-Disk | Where-Object { $_.IsBoot -eq $true } | Select-Object -First 1
        $dataDisks = Get-Disk | Where-Object { $_.IsBoot -eq $false }

        if ($bootDisk) {
            Write-ScriptLog "Boot Disk: Disk $($bootDisk.Number) - $($bootDisk.Model)" -Level "Info"

            # Try to expand OS partition if needed
            try {
                $currentSize = (Get-Partition -DriveLetter C).Size
                $maxSize = (Get-PartitionSupportedSize -DriveLetter C).SizeMax

                if ($currentSize -lt ($maxSize - 1GB)) {
                    Write-ScriptLog "Expanding OS partition..." -Level "Info"
                    Resize-Partition -DriveLetter C -Size $maxSize
                    Write-ScriptLog "OS partition expanded successfully" -Level "Success"
                } else {
                    Write-ScriptLog "OS partition already at maximum size" -Level "Info"
                }
            } catch {
                Write-ScriptLog "Could not resize OS partition: $_" -Level "Warning"
            }
        }

        # Configure data disks if present
        if ($dataDisks.Count -gt 0) {
            Write-ScriptLog "Found $($dataDisks.Count) data disk(s)" -Level "Info"

            foreach ($disk in $dataDisks) {
                if ($disk.PartitionStyle -eq 'RAW') {
                    Write-ScriptLog "Initializing Disk $($disk.Number)..." -Level "Info"
                    Initialize-Disk -Number $disk.Number -PartitionStyle GPT
                    $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
                    Format-Volume -DriveLetter $part.DriveLetter -FileSystem NTFS -NewFileSystemLabel "data1"
                    Write-ScriptLog "Configured Disk $($disk.Number) as $($part.DriveLetter): drive" -Level "Success"
                }
            }
        }
    } catch {
        Write-ScriptLog "Storage configuration error: $_" -Level "Warning"
    }
    #endregion

    #region Step 2: Filesystem Configuration
    Write-ScriptLog "Step 2: Creating Directory Structure..." -Level "Info"

    try {
        # Check if D: drive exists, otherwise use C:
        $targetDrive = if (Test-Path "D:\") { "D:" } else { "C:" }

        New-Item -Path "$targetDrive\repo" -ItemType Directory -Force | Out-Null
        Write-ScriptLog "Created repository directory at $targetDrive\repo" -Level "Success"
    } catch {
        Write-ScriptLog "Directory creation error: $_" -Level "Warning"
    }
    #endregion

    #region Step 3: Network Configuration
    if (-not $Config.SkipNetworkTeaming) {
        Write-ScriptLog "Step 3: Configuring Network Teaming..." -Level "Info"

        if ($Config.NonInteractive) {
            Write-ScriptLog "Network teaming skipped in RMM mode - configure manually if needed" -Level "Warning"
        } else {
            # Interactive network configuration would go here
            Write-ScriptLog "Manual network configuration available in interactive mode" -Level "Info"
        }
    } else {
        Write-ScriptLog "Step 3: Skipping network teaming" -Level "Info"
    }
    #endregion

    #region Step 4: Windows Configuration
    Write-ScriptLog "Step 4: Configuring Windows Settings..." -Level "Info"

    try {
        # Disable Windows Firewall (temporarily for setup)
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

        # Set machine inactivity limit
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' `
                        -Name 'InactivityTimeoutSecs' -PropertyType DWORD -Value 0x00000384 -Force -ErrorAction SilentlyContinue

        # Disable Server Manager auto-start
        Get-ScheduledTask -TaskName ServerManager -ErrorAction SilentlyContinue | Disable-ScheduledTask

        # Enable registry backup
        New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Configuration Manager\' `
                        -Name 'EnablePeriodicBackup' -PropertyType DWORD -Value 0x00000001 -Force -ErrorAction SilentlyContinue

        # Enable RDP
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

        Write-ScriptLog "Windows settings configured" -Level "Success"
    } catch {
        Write-ScriptLog "Windows configuration error: $_" -Level "Warning"
    }
    #endregion

    #region Step 5: Install Windows Features
    Write-ScriptLog "Step 5: Installing Windows Features..." -Level "Info"

    try {
        # Install OpenSSH
        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

        Start-Service sshd
        Set-Service -Name sshd -StartupType 'Automatic'

        # Configure SSH firewall
        Set-NetFirewallRule -Name OpenSSH-Server-In-TCP -Profile Private,Domain

        # Set default shell for SSH
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell `
                        -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

        Write-ScriptLog "Windows features installed" -Level "Success"
    } catch {
        Write-ScriptLog "Feature installation error: $_" -Level "Warning"
    }
    #endregion

    #region Step 6: Install OEM Tools
    Write-ScriptLog "Step 6: Installing OEM Tools..." -Level "Info"

    try {
        $Manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer

        if ($Manufacturer -like "Dell*") {
            Write-ScriptLog "Dell hardware detected - installing OpenManage" -Level "Info"

            # Download URLs for Dell tools
            $omsaUrl = "https://dl.dell.com/FOLDER11337880M/1/Windows_OMSA_11.0.1.0_A00.exe"
            $ismUrl = "https://dl.dell.com/FOLDER11034445M/1/iDRAC-Service-Module-5.3.0.0_Windows_x64.exe"

            $wc = New-Object System.Net.WebClient

            try {
                Write-ScriptLog "Downloading OpenManage Server Administrator..." -Level "Info"
                $wc.DownloadFile($omsaUrl, "$env:windir\temp\OMSA_Setup.exe")
                Start-Process -FilePath "$env:windir\temp\OMSA_Setup.exe" -ArgumentList "/s" -Wait -NoNewWindow
                Write-ScriptLog "OpenManage installed" -Level "Success"
            } catch {
                Write-ScriptLog "Could not install OpenManage: $_" -Level "Warning"
            }

            try {
                Write-ScriptLog "Downloading iDRAC Service Module..." -Level "Info"
                $wc.DownloadFile($ismUrl, "$env:windir\temp\ISM_Setup.exe")
                Start-Process -FilePath "$env:windir\temp\ISM_Setup.exe" -ArgumentList "/s" -Wait -NoNewWindow
                Write-ScriptLog "iDRAC Service Module installed" -Level "Success"
            } catch {
                Write-ScriptLog "Could not install iDRAC Service Module: $_" -Level "Warning"
            }
        } else {
            Write-ScriptLog "Non-Dell hardware - skipping OEM tools" -Level "Info"
        }
    } catch {
        Write-ScriptLog "OEM tools installation error: $_" -Level "Warning"
    }
    #endregion

    #region Step 7: Install Applications
    Write-ScriptLog "Step 7: Installing Applications..." -Level "Info"

    # Check for WinGet
    $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetPath) {
        $apps = @(
            @{id = "Mozilla.Firefox"; name = "Firefox"},
            @{id = "7zip.7zip"; name = "7-Zip"},
            @{id = "Microsoft.VisualStudioCode"; name = "Visual Studio Code"},
            @{id = "Notepad++.Notepad++"; name = "Notepad++"}
        )

        foreach ($app in $apps) {
            try {
                Write-ScriptLog "Installing $($app.name)..." -Level "Info"
                winget install --id $app.id --exact --silent --accept-package-agreements --accept-source-agreements
            } catch {
                Write-ScriptLog "Could not install $($app.name): $_" -Level "Warning"
            }
        }
    } else {
        Write-ScriptLog "WinGet not available - skipping application installation" -Level "Warning"
    }
    #endregion

    #region Step 8: Active Directory Domain Services
    if ($Config.InstallADDS) {
        Write-ScriptLog "Step 8: Installing Active Directory Domain Services..." -Level "Info"

        try {
            # Install AD DS role
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
            Write-ScriptLog "AD DS role installed" -Level "Success"

            # Install DNS Server
            Install-WindowsFeature -Name DNS -IncludeManagementTools
            Write-ScriptLog "DNS Server role installed" -Level "Success"

            # Install DHCP if requested
            if ($Config.InstallDHCP) {
                Install-WindowsFeature -Name DHCP -IncludeManagementTools
                Write-ScriptLog "DHCP Server role installed" -Level "Success"
            }

            Write-ScriptLog "" -Level "Info"
            Write-ScriptLog "IMPORTANT: Domain promotion must be done manually" -Level "Warning"
            Write-ScriptLog "To promote this server as the first domain controller in a new forest:" -Level "Info"
            Write-ScriptLog "Install-ADDSForest -DomainName '$($Config.DomainName)' -DomainNetBiosName '$($Config.NetBIOSName)' -InstallDns" -Level "Info"
            Write-ScriptLog "" -Level "Info"
            Write-ScriptLog "To add as additional DC to existing domain:" -Level "Info"
            Write-ScriptLog "Install-ADDSDomainController -DomainName '$($Config.DomainName)' -Credential (Get-Credential)" -Level "Info"

            $Global:RestartRequired = $true
        } catch {
            Write-ScriptLog "AD DS installation error: $_" -Level "Error"
        }
    } else {
        Write-ScriptLog "Step 8: Skipping AD DS installation" -Level "Info"
    }
    #endregion

    #region Step 9: Windows Updates
    if (-not $Config.SkipWindowsUpdate) {
        Write-ScriptLog "Step 9: Installing Windows Updates..." -Level "Info"

        try {
            Install-PackageProvider -Name NuGet -Force
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
            Install-Module PSWindowsUpdate -Force
            Get-WindowsUpdate -AcceptAll -Install
            Write-ScriptLog "Windows updates completed" -Level "Success"
        } catch {
            Write-ScriptLog "Windows Update error: $_" -Level "Warning"
        }
    } else {
        Write-ScriptLog "Step 9: Skipping Windows Updates" -Level "Info"
    }
    #endregion

    Write-ScriptLog "========================================" -Level "Info"
    Write-ScriptLog "Domain Controller Setup Complete!" -Level "Success"
    Write-ScriptLog "Server Name: $NewComputerName" -Level "Success"
    Write-ScriptLog "========================================" -Level "Info"

    if ($Config.InstallADDS) {
        Write-ScriptLog "" -Level "Warning"
        Write-ScriptLog "Next Steps:" -Level "Warning"
        Write-ScriptLog "1. Restart server to complete installation" -Level "Warning"
        Write-ScriptLog "2. Run domain promotion command (see above)" -Level "Warning"
        Write-ScriptLog "3. Configure DNS settings" -Level "Warning"
        Write-ScriptLog "4. Configure DHCP scopes if installed" -Level "Warning"
    }

    if ($Global:RestartRequired) {
        Write-ScriptLog "RESTART REQUIRED to complete configuration" -Level "Warning"

        if ($Config.NonInteractive) {
            Write-ScriptLog "Server will restart automatically in 60 seconds" -Level "Warning"
            shutdown /r /t 60 /c "Domain Controller Setup Complete - Restarting"
        } else {
            $restart = Read-Host "Restart now? (y/n)"
            if ($restart -eq 'y') {
                Restart-Computer -Force
            }
        }
    }

} catch {
    Write-ScriptLog "Setup failed: $_" -Level "Error"
    exit 1
}

Stop-Transcript