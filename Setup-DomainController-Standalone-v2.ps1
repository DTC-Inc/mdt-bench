<#
.SYNOPSIS
    Complete Standalone Domain Controller Setup Script - Environment Variable Version
.DESCRIPTION
    Single-file setup script for Domain Controller VMs with all configurations
    consolidated. Uses environment variables for RMM deployment.
.NOTES
    Author: DTC Inc
    Version: 2.0 Standalone (Environment Variables)
    Date: 2024-12-18

    Environment Variables:
    - MDT_SERVER_SEQUENCE: Server sequence number (01-99)
    - MDT_COMPANY_NAME: Company name for branding (default: DTC)
    - MDT_SKIP_WINDOWS_UPDATE: Skip Windows Updates (true/false)
    - MDT_SKIP_NETWORK_TEAMING: Skip network team configuration (true/false)
    - MDT_INSTALL_ADDS: Install AD DS role (true/false)
    - MDT_DOMAIN_NAME: Domain name for new forest (default: corp.local)
    - MDT_NETBIOS_NAME: NetBIOS domain name (default: CORP)
    - MDT_INSTALL_DHCP: Install DHCP Server role (true/false)
    - MDT_LOG_PATH: Custom log path (default: C:\Logs\MDT)
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

# Script Configuration from Environment Variables
$Config = @{
    ServerSequence = $env:MDT_SERVER_SEQUENCE
    CompanyName = if ($env:MDT_COMPANY_NAME) { $env:MDT_COMPANY_NAME } else { "DTC" }
    SkipWindowsUpdate = $env:MDT_SKIP_WINDOWS_UPDATE -eq 'true' -or $env:MDT_SKIP_WINDOWS_UPDATE -eq '1' -or $env:MDT_SKIP_WINDOWS_UPDATE -eq 'yes'
    SkipNetworkTeaming = $env:MDT_SKIP_NETWORK_TEAMING -eq 'true' -or $env:MDT_SKIP_NETWORK_TEAMING -eq '1' -or $env:MDT_SKIP_NETWORK_TEAMING -eq 'yes'
    InstallADDS = $env:MDT_INSTALL_ADDS -eq 'true' -or $env:MDT_INSTALL_ADDS -eq '1' -or $env:MDT_INSTALL_ADDS -eq 'yes'
    DomainName = if ($env:MDT_DOMAIN_NAME) { $env:MDT_DOMAIN_NAME } else { "corp.local" }
    NetBIOSName = if ($env:MDT_NETBIOS_NAME) { $env:MDT_NETBIOS_NAME } else { "CORP" }
    InstallDHCP = $env:MDT_INSTALL_DHCP -eq 'true' -or $env:MDT_INSTALL_DHCP -eq '1' -or $env:MDT_INSTALL_DHCP -eq 'yes'
    LogPath = if ($env:MDT_LOG_PATH) { $env:MDT_LOG_PATH } else { "C:\Logs\MDT" }
}

# Server Role Code for Domain Controller
$ServerRole = "DC"

# Create log directory
if (!(Test-Path $Config.LogPath)) {
    New-Item -ItemType Directory -Path $Config.LogPath -Force | Out-Null
}

$LogFile = Join-Path $Config.LogPath "DomainController-Setup-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"

    switch ($Level) {
        "Error" { Write-Host $LogMessage -ForegroundColor Red }
        "Warning" { Write-Host $LogMessage -ForegroundColor Yellow }
        "Success" { Write-Host $LogMessage -ForegroundColor Green }
        default { Write-Host $LogMessage }
    }

    Add-Content -Path $LogFile -Value $LogMessage
}

# Error handling
$ErrorActionPreference = "Stop"
trap {
    Write-Log -Message "ERROR: $_" -Level "Error"
    Write-Log -Message "Setup failed at line $($_.InvocationInfo.ScriptLineNumber)" -Level "Error"
    exit 1
}

# Main setup process
try {
    Write-Log "========================================" -Level "Info"
    Write-Log "Starting Domain Controller Setup (v2)" -Level "Info"
    Write-Log "Company: $($Config.CompanyName)" -Level "Info"
    Write-Log "========================================" -Level "Info"

    # Display configuration
    Write-Log "Configuration:" -Level "Info"
    Write-Log "  Skip Windows Update: $($Config.SkipWindowsUpdate)" -Level "Info"
    Write-Log "  Skip Network Teaming: $($Config.SkipNetworkTeaming)" -Level "Info"
    Write-Log "  Install AD DS: $($Config.InstallADDS)" -Level "Info"
    Write-Log "  Domain Name: $($Config.DomainName)" -Level "Info"
    Write-Log "  NetBIOS Name: $($Config.NetBIOSName)" -Level "Info"
    Write-Log "  Install DHCP: $($Config.InstallDHCP)" -Level "Info"
    Write-Log "" -Level "Info"

    #region Step 0: Server Naming
    Write-Log "Step 0: Configuring Server Name..." -Level "Info"
    try {
        $currentName = $env:COMPUTERNAME

        # Check if server sequence is provided, otherwise prompt
        if ([string]::IsNullOrEmpty($Config.ServerSequence)) {
            do {
                $sequence = Read-Host "Enter the sequence number for this Domain Controller (1-99)"
                if ($sequence -match '^\d{1,2}$' -and [int]$sequence -ge 1 -and [int]$sequence -le 99) {
                    $Config.ServerSequence = "{0:d2}" -f [int]$sequence
                    break
                }
                Write-Host "Invalid input. Please enter a number between 1 and 99." -ForegroundColor Yellow
            } while ($true)
        } else {
            # Validate and format the provided sequence
            if ($Config.ServerSequence -match '^\d{1,2}$' -and [int]$Config.ServerSequence -ge 1 -and [int]$Config.ServerSequence -le 99) {
                $Config.ServerSequence = "{0:d2}" -f [int]$Config.ServerSequence
            } else {
                Write-Log "Invalid server sequence provided: $($Config.ServerSequence). Using default 01." -Level "Warning"
                $Config.ServerSequence = "01"
            }
        }

        # Generate new computer name
        $NewComputerName = "${ServerRole}$($Config.ServerSequence)"

        if ($currentName -ne $NewComputerName) {
            Write-Log "Renaming computer from $currentName to $NewComputerName" -Level "Info"
            Rename-Computer -NewName $NewComputerName -Force
            Write-Log "Computer renamed to $NewComputerName. Restart required." -Level "Success"
            $RestartRequired = $true
        } else {
            Write-Log "Computer name already set to $NewComputerName" -Level "Info"
        }
    } catch {
        Write-Log "Server naming error: $_" -Level "Warning"
    }
    #endregion

    #region Storage Configuration
    Write-Log "Step 1: Configuring Storage..." -Level "Info"
    try {
        $errorCatch = $true
        while ($errorCatch -eq $true) {
            # Check environment variable first
            $inputBoot = $env:MDT_DEDICATED_BOOT_DISK

            if ([string]::IsNullOrEmpty($inputBoot)) {
                $inputBoot = Read-Host "Does this server have a dedicated boot disk? (y or n)"
            }

            Write-Host "You chose $inputBoot."

            if ($inputBoot -eq "y" -or $inputBoot -eq "n") {
                if ($inputBoot -eq "y") {
                    # Expand OS partition
                    $maxSize = (Get-PartitionSupportedSize -DriveLetter C).sizeMax
                    Resize-Partition -DriveLetter C -size $maxSize

                    # Create data1 partition
                    $dataDisk = Get-Disk | Where-Object -Property isBoot -NE $true | Select-Object -ExpandProperty number
                    Initialize-Disk -partitionStyle GPT -number $dataDisk
                    New-Partition -DiskNumber $dataDisk -useMaximumSize -DriveLetter D
                    Format-Volume -fileSystem NTFS -DriveLetter D
                    Get-Volume | Where-Object -Property driveLetter -EQ D | Set-Volume -newFileSystemLabel data1
                } else {
                    # Expand OS partition
                    Resize-Partition -DriveLetter C -size 120GB

                    # Create data1 partition
                    New-Partition -DiskNumber 0 -useMaximumSize -DriveLetter D
                    Format-Volume -fileSystem NTFS -DriveLetter D
                    Get-Volume | Where-Object -Property driveLetter -EQ D | Set-Volume -newFileSystemLabel data1
                }
                $errorCatch = $false
            } else {
                Write-Host "Input not accepted. Try again."
            }
        }
        Write-Log "Storage configuration completed" -Level "Info"
    } catch {
        Write-Log "Storage configuration error: $_" -Level "Warning"
    }
    #endregion

    #region Filesystem Configuration
    Write-Log "Step 2: Configuring Filesystem..." -Level "Info"
    try {
        if (Test-Path D:\) {
            New-Item -path D:\ -name 'repo' -itemtype directory -Force
        }
        Write-Log "Filesystem configuration completed" -Level "Info"
    } catch {
        Write-Log "Filesystem configuration error: $_" -Level "Warning"
    }
    #endregion

    #region Network Configuration
    Write-Log "Step 3: Configuring Network..." -Level "Info"
    if (!$Config.SkipNetworkTeaming) {
        try {
            $Ready = "n"
            while ($Ready -ne "r") {
                $Ready = Read-Host "Please patch in NICs to team. Type 'r' when ready"
                if ($Ready -eq "r") {
                    Write-Host "Ready to configure network teams!"
                } else {
                    Write-Host "Waiting for network cables to be connected..."
                }
            }

            $finished = "n"
            $HyperV = Get-WindowsFeature | Where Installed | Select -ExpandProperty Name

            Start-Sleep -Seconds 10

            # Create NIC team(s) based off of link-state
            $count = 0
            while ( $finished -eq "n" ) {
                $count = $count + 1
                $nicList = Get-NetAdapter | Where -Property DriverFileName -notlike "usb*"| Where -Property Name -notlike vEthernet* | Where -Property Status -eq 'Up' | Where -Property InterFaceDescription -notcontains Hyper-V* | Select -ExpandProperty Name

                if ($count -eq 1) {
                    if ($HyperV -eq "Hyper-V") {
                        # Remove Hyper-V Teams
                        Get-VMNetworkAdapter -managementOS | Where-Object -Property "name" -NotLike "Container NIC*" | Remove-VMNetworkAdapter
                        Get-VMSwitch | Where-Object -Property name -NotLike "Default Switch" | Remove-VMSwitch -Force
                        Start-Sleep -Seconds 10

                        # Create Hyper-V initial Team
                        New-VMSwitch -Name SET$count -netAdapterName $nicList -enableEmbeddedTeaming $true
                        Rename-VmNetworkAdapter -Name SET$count -NewName vNIC1-SET$count -ManagementOs
                        Add-VmNetworkAdapter -Name vNIC2-SET$count -SwitchName SET$count -ManagementOs
                    } else {
                        Get-NetLbfoTeam | Remove-NetLbfoTeam -confirm:$false
                        Start-Sleep -Seconds 10

                        New-NetLbfoTeam -Name TEAM$count -TeamMembers $nicList -LoadBalancingAlgorithm Dynamic -TeamingMode SwitchIndependent -Confirm:$False
                    }
                } else {
                    if ($HyperV -eq "Hyper-V") {
                        New-VMSwitch -Name SET$count -netAdapterName $nicList -enableEmbeddedTeaming $true -AllowManagementOs $False
                    } else {
                        New-NetLbfoTeam -Name TEAM$count -TeamMembers $nicList -LoadBalancingAlgorithm Dynamic -TeamingMode SwitchIndependent -Confirm:$False
                    }
                }
                $finished = Read-Host "Are you finished? y/n"
            }
            Write-Log "Network configuration completed" -Level "Info"
        } catch {
            Write-Log "Network configuration error: $_" -Level "Warning"
        }
    } else {
        Write-Log "Skipping network teaming configuration" -Level "Info"
    }
    #endregion

    #region User Profile Configuration
    Write-Log "Step 4: Configuring User Profiles..." -Level "Info"
    try {
        # Clear Start Menu
        $Url = 'https://s3.us-west-002.backblazeb2.com/public-dtc/repo/config/windows/start-menu-cleared.xml'
        wget $Url -OutFile $Env:WINDIR\temp\LayoutModification.xml

        Copy-Item $Env:WINDIR'\temp\LayoutModification.xml' -Destination $Env:LOCALAPPDATA'\Microsoft\Windows\Shell'
        Copy-Item $Env:WINDIR'\temp\LayoutModification.xml' -Destination $Env:SYSTEMDRIVE'\Users\Default\AppData\Local\Microsoft\Windows\Shell'

        Write-Log "User profile configuration completed" -Level "Info"
    } catch {
        Write-Log "User profile configuration error: $_" -Level "Warning"
    }
    #endregion

    #region Windows Configuration
    Write-Log "Step 5: Configuring Windows Settings..." -Level "Info"
    try {
        # Disable Firewall
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

        # Set machine inactivity limit to 900 seconds
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name 'InactivityTimeoutSecs' -PropertyType DWORD -Value 0x00000384 -Force -ea 'SilentlyContinue'

        # Disable ServerManager from auto starting
        Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask -Verbose

        # Enable registry backup
        New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Configuration Manager\' -Name 'EnablePeriodicBackup' -PropertyType DWORD -Value 0x00000001 -Force -ea 'SilentlyContinue'

        Write-Log "Windows configuration completed" -Level "Info"
    } catch {
        Write-Log "Windows configuration error: $_" -Level "Warning"
    }
    #endregion

    #region Deploy Windows Features
    Write-Log "Step 6: Installing Windows Features..." -Level "Info"
    try {
        # Install the OpenSSH Client
        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

        # Install the OpenSSH Server
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

        Start-Service sshd
        Set-Service -Name sshd -StartupType 'Automatic'

        # Change profile from Any to Private & Domain
        Set-NetFirewallRule -Name OpenSSH-Server-In-TCP -Profile Private,Domain

        # Apply Default Shell
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

        Write-Log "Windows features installed" -Level "Info"
    } catch {
        Write-Log "Feature deployment error: $_" -Level "Warning"
    }
    #endregion

    #region Deploy OEM Tools
    Write-Log "Step 7: Installing OEM Tools..." -Level "Info"
    try {
        $Manufacturer = Get-CimInstance -ClassName Win32_ComputerSystem | Select -ExpandProperty Manufacturer

        if ($Manufacturer -like "Dell*") {
            Write-Log "Dell hardware detected - installing OpenManage" -Level "Info"
            $progressPreference = 'SilentlyContinue'

            # Download latest OpenManage Server Administrator (OMSA) directly from Dell
            # Note: These are the latest stable URLs as of 2024
            # OMSA 11.0.1.0 for Windows Server 2025
            $omsaUrl = "https://dl.dell.com/FOLDER11337880M/1/Windows_OMSA_11.0.1.0_A00.exe"
            $ismUrl = "https://dl.dell.com/FOLDER11034445M/1/iDRAC-Service-Module-5.3.0.0_Windows_x64.exe"

            Write-Log "Downloading OpenManage Server Administrator..." -Level "Info"
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($omsaUrl, "$env:windir\temp\OMSA_Setup.exe")

            Write-Log "Downloading iDRAC Service Module..." -Level "Info"
            $wc.DownloadFile($ismUrl, "$env:windir\temp\ISM_Setup.exe")

            # Install OMSA silently
            Write-Log "Installing OpenManage Server Administrator..." -Level "Info"
            Start-Process -FilePath "$env:windir\temp\OMSA_Setup.exe" -ArgumentList "/s" -Wait -NoNewWindow

            # Install iDRAC Service Module silently
            Write-Log "Installing iDRAC Service Module..." -Level "Info"
            Start-Process -FilePath "$env:windir\temp\ISM_Setup.exe" -ArgumentList "/s" -Wait -NoNewWindow

            Write-Log "Dell OpenManage installation completed" -Level "Info"

            # Optional: Install Dell System Update (DSU) for driver updates
            $dsuUrl = "https://dl.dell.com/FOLDER11689994M/1/Systems-Management_Application_NVD8W_WN64_2.0.2.3_A00.EXE"
            Write-Log "Downloading Dell System Update..." -Level "Info"
            $wc.DownloadFile($dsuUrl, "$env:windir\temp\DSU_Setup.exe")

            Write-Log "Installing Dell System Update..." -Level "Info"
            Start-Process -FilePath "$env:windir\temp\DSU_Setup.exe" -ArgumentList "/s" -Wait -NoNewWindow

        } else {
            Write-Log "Non-Dell hardware - skipping OEM tools" -Level "Info"
        }
        Write-Log "OEM tools installation completed" -Level "Info"
    } catch {
        Write-Log "OEM tools deployment error: $_" -Level "Warning"
    }
    #endregion

    #region Deploy Applications
    Write-Log "Step 8: Installing Applications..." -Level "Info"
    try {
        # Check if WinGet is available (Windows 11/Server 2025)
        $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
        if (!$wingetPath) {
            Write-Log "WinGet not found. Please ensure Windows Server 2025 or Windows 11 is installed." -Level "Error"
            throw "WinGet is required but not found"
        }

        # Install applications via WinGet
        $apps = @(
            @{id = "Mozilla.Firefox"; name = "Firefox"},
            @{id = "7zip.7zip"; name = "7-Zip"},
            @{id = "Microsoft.VisualStudioCode"; name = "Visual Studio Code"},
            @{id = "Microsoft.VCRedist.2015+.x64"; name = "Visual C++ Redistributable"},
            @{id = "Notepad++.Notepad++"; name = "Notepad++"}
        )

        foreach ($app in $apps) {
            Write-Log "Installing $($app.name)..." -Level "Info"
            winget install --id $app.id --exact --silent --accept-package-agreements --accept-source-agreements
        }

        Write-Log "Applications installed" -Level "Info"
    } catch {
        Write-Log "Application deployment error: $_" -Level "Warning"
    }
    #endregion

    #region Windows Updates
    if (!$Config.SkipWindowsUpdate) {
        Write-Log "Step 9: Installing Windows Updates..." -Level "Info"
        try {
            Install-PackageProvider -Name NuGet -Force
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
            Install-Module PSWindowsUpdate -Force
            Get-WindowsUpdate -AcceptAll -Install
            Write-Log "Windows updates completed" -Level "Info"
        } catch {
            Write-Log "Windows Update error: $_" -Level "Warning"
        }
    } else {
        Write-Log "Step 9: Skipping Windows Updates (per configuration)" -Level "Info"
    }
    #endregion

    #region Active Directory Domain Services
    if ($Config.InstallADDS) {
        Write-Log "Step 10: Installing Active Directory Domain Services..." -Level "Info"
        try {
            # Install AD DS role
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

            # Install DNS Server
            Install-WindowsFeature -Name DNS -IncludeManagementTools

            # Install DHCP Server if configured
            if ($Config.InstallDHCP) {
                Install-WindowsFeature -Name DHCP -IncludeManagementTools
                Write-Log "DHCP Server installed" -Level "Info"
            }

            Write-Log "Active Directory Domain Services installed" -Level "Success"
            Write-Log "" -Level "Info"
            Write-Log "IMPORTANT: Domain promotion must be done manually" -Level "Warning"

            Write-Log "To promote this server as the first domain controller in a new forest:" -Level "Info"
            Write-Log "Install-ADDSForest -DomainName '$($Config.DomainName)' -DomainNetBiosName '$($Config.NetBIOSName)' -InstallDns" -Level "Info"

            Write-Log "" -Level "Info"
            Write-Log "To add as additional DC to existing domain:" -Level "Info"
            Write-Log "Install-ADDSDomainController -DomainName '$($Config.DomainName)' -Credential (Get-Credential)" -Level "Info"
        } catch {
            Write-Log "AD DS installation error: $_" -Level "Warning"
        }
    } else {
        Write-Log "Step 10: Skipping AD DS installation (set MDT_INSTALL_ADDS=true to enable)" -Level "Info"
    }
    #endregion

    Write-Log "========================================" -Level "Success"
    Write-Log "Domain Controller Base Setup Complete!" -Level "Success"
    Write-Log "Server Name: $NewComputerName" -Level "Success"
    Write-Log "========================================" -Level "Success"
    Write-Log "" -Level "Info"
    Write-Log "Next Steps:" -Level "Info"
    Write-Log "1. Restart server to apply computer name change" -Level "Info"
    Write-Log "2. Set static IP address for this server" -Level "Info"
    Write-Log "3. Install Active Directory Domain Services if not done:" -Level "Info"
    Write-Log "   Set MDT_INSTALL_ADDS=true and re-run script" -Level "Info"
    Write-Log "4. Promote to Domain Controller using:" -Level "Info"
    Write-Log "   - For new forest: Install-ADDSForest" -Level "Info"
    Write-Log "   - For additional DC: Install-ADDSDomainController" -Level "Info"
    Write-Log "5. Configure DNS settings" -Level "Info"
    Write-Log "6. Configure DHCP if needed" -Level "Info"
    Write-Log "" -Level "Info"
    Write-Log "Log file: $LogFile" -Level "Info"
    Write-Log "" -Level "Info"
    Write-Log "Environment variables detected:" -Level "Info"
    Get-ChildItem env:MDT_* | ForEach-Object {
        Write-Log "  $($_.Name) = $($_.Value)" -Level "Info"
    }

    # Prompt for restart if name was changed
    if ($RestartRequired) {
        Write-Log "" -Level "Warning"
        Write-Log "RESTART REQUIRED: Computer name was changed to $NewComputerName" -Level "Warning"
        $restart = Read-Host "Restart now? (y/n)"
        if ($restart -eq 'y') {
            Write-Log "Restarting computer..." -Level "Info"
            Restart-Computer -Force
        }
    } else {
        # Normal restart prompt
        $restart = Read-Host "Setup complete. Restart now? (y/n)"
        if ($restart -eq 'y') {
            Write-Log "Restarting computer..." -Level "Info"
            Restart-Computer -Force
        }
    }

} catch {
    Write-Log -Message "Setup failed: $_" -Level "Error"
    Write-Log -Message "Please review the log file at: $LogFile" -Level "Error"
    exit 1
}