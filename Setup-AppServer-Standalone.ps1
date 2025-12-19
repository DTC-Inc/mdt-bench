<#
.SYNOPSIS
    Complete Standalone Application Server Setup Script
.DESCRIPTION
    Single-file setup script for Application Server VMs with all configurations
    consolidated. No external script dependencies. Includes IIS and SQL options.
.NOTES
    Author: DTC Inc
    Version: 2.0 Standalone
    Date: 2024-12-18
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$SkipWindowsUpdate,

    [Parameter()]
    [switch]$SkipNetworkTeaming,

    [Parameter()]
    [switch]$InstallIIS,

    [Parameter()]
    [switch]$InstallSQL,

    [Parameter()]
    [switch]$InstallDotNet,

    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\Logs\AppServer-Standalone-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"
)

# Create log directory if it doesn't exist
$LogDir = Split-Path $LogPath -Parent
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogPath -Value $LogMessage
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
    Write-Log "Starting Application Server Standalone Setup" -Level "Info"
    Write-Log "========================================" -Level "Info"

    #region Storage Configuration
    Write-Log "Step 1: Configuring Storage..." -Level "Info"
    try {
        $errorCatch = $true
        while ($errorCatch -eq $true) {
            $inputBoot = Read-Host "Does this server have a dedicated boot disk? (y or n)"
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
            New-Item -path D:\ -name 'apps' -itemtype directory -Force
            New-Item -path D:\ -name 'data' -itemtype directory -Force
        }
        Write-Log "Filesystem configuration completed" -Level "Info"
    } catch {
        Write-Log "Filesystem configuration error: $_" -Level "Warning"
    }
    #endregion

    #region Network Configuration
    Write-Log "Step 3: Configuring Network..." -Level "Info"
    if (!$SkipNetworkTeaming) {
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

        # Install .NET Framework if requested
        if ($InstallDotNet) {
            Write-Log "Installing .NET Framework features..." -Level "Info"
            Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All
            Enable-WindowsOptionalFeature -Online -FeatureName NetFx4-AdvSrvs -All
            Enable-WindowsOptionalFeature -Online -FeatureName NetFx4Extended-ASPNET45 -All
        }

        Write-Log "Windows features installed" -Level "Info"
    } catch {
        Write-Log "Feature deployment error: $_" -Level "Warning"
    }
    #endregion

    #region Install IIS
    if ($InstallIIS) {
        Write-Log "Step 7: Installing IIS and Web Features..." -Level "Info"
        try {
            # Install IIS with common features
            Enable-WindowsOptionalFeature -Online -FeatureName `
                IIS-WebServerRole, `
                IIS-WebServer, `
                IIS-CommonHttpFeatures, `
                IIS-HttpErrors, `
                IIS-HttpRedirect, `
                IIS-ApplicationDevelopment, `
                IIS-NetFxExtensibility45, `
                IIS-HealthAndDiagnostics, `
                IIS-HttpLogging, `
                IIS-Security, `
                IIS-RequestFiltering, `
                IIS-Performance, `
                IIS-WebServerManagementTools, `
                IIS-IIS6ManagementCompatibility, `
                IIS-Metabase, `
                IIS-ManagementConsole, `
                IIS-BasicAuthentication, `
                IIS-WindowsAuthentication, `
                IIS-StaticContent, `
                IIS-DefaultDocument, `
                IIS-DirectoryBrowsing, `
                IIS-ASPNET45 `
                -All

            # Create application pool directories
            if (Test-Path D:\) {
                New-Item -Path "D:\inetpub" -ItemType Directory -Force
                New-Item -Path "D:\inetpub\wwwroot" -ItemType Directory -Force
                New-Item -Path "D:\inetpub\logs" -ItemType Directory -Force
            }

            Write-Log "IIS and web features installed successfully" -Level "Info"
        } catch {
            Write-Log "IIS installation error: $_" -Level "Warning"
        }
    } else {
        Write-Log "Step 7: Skipping IIS installation" -Level "Info"
    }
    #endregion

    #region Deploy OEM Tools
    Write-Log "Step 8: Installing OEM Tools..." -Level "Info"
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
    Write-Log "Step 9: Installing Applications..." -Level "Info"
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
            @{id = "Notepad++.Notepad++"; name = "Notepad++"},
            @{id = "Git.Git"; name = "Git"}
        )

        foreach ($app in $apps) {
            Write-Log "Installing $($app.name)..." -Level "Info"
            winget install --id $app.id --exact --silent --accept-package-agreements --accept-source-agreements
        }

        # Install SQL Server if requested
        if ($InstallSQL) {
            Write-Log "Installing SQL Server Express..." -Level "Info"
            winget install --id Microsoft.SQLServer.2022.Express --exact --silent --accept-package-agreements --accept-source-agreements

            Write-Log "Installing SQL Server Management Studio..." -Level "Info"
            winget install --id Microsoft.SQLServerManagementStudio --exact --silent --accept-package-agreements --accept-source-agreements
        }

        Write-Log "Applications installed" -Level "Info"
    } catch {
        Write-Log "Application deployment error: $_" -Level "Warning"
    }
    #endregion

    #region Windows Updates
    if (!$SkipWindowsUpdate) {
        Write-Log "Step 10: Installing Windows Updates..." -Level "Info"
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
        Write-Log "Step 10: Skipping Windows Updates (per parameter)" -Level "Info"
    }
    #endregion

    Write-Log "========================================" -Level "Info"
    Write-Log "Application Server Setup Complete!" -Level "Info"
    Write-Log "========================================" -Level "Info"
    Write-Log "" -Level "Info"
    Write-Log "Installed Components:" -Level "Info"

    if ($InstallIIS) {
        Write-Log "✓ IIS Web Server" -Level "Info"
        Write-Log "  - Default website location: C:\inetpub\wwwroot" -Level "Info"
        Write-Log "  - Alternative location created: D:\inetpub\wwwroot" -Level "Info"
    }

    if ($InstallSQL) {
        Write-Log "✓ SQL Server Express" -Level "Info"
        Write-Log "✓ SQL Server Management Studio" -Level "Info"
    }

    if ($InstallDotNet) {
        Write-Log "✓ .NET Framework (all versions)" -Level "Info"
    }

    Write-Log "" -Level "Info"
    Write-Log "Next Steps:" -Level "Info"
    Write-Log "1. Configure application-specific settings" -Level "Info"
    Write-Log "2. Set up database connections if required" -Level "Info"
    Write-Log "3. Configure firewall rules for your applications" -Level "Info"
    Write-Log "4. Join to domain if required" -Level "Info"
    Write-Log "5. Configure backup solutions" -Level "Info"
    Write-Log "" -Level "Info"
    Write-Log "Review log file at: $LogPath" -Level "Info"

    # Prompt for restart
    $restart = Read-Host "Setup complete. Restart now? (y/n)"
    if ($restart -eq 'y') {
        Write-Log "Restarting computer..." -Level "Info"
        Restart-Computer -Force
    }

} catch {
    Write-Log -Message "Setup failed: $_" -Level "Error"
    Write-Log -Message "Please review the log file at: $LogPath" -Level "Error"
    exit 1
}