<#
.SYNOPSIS
    Complete Standalone Workstation Setup Script
.DESCRIPTION
    Single-file setup script for Windows workstations with all configurations,
    debloating, and optimizations consolidated. No external script dependencies.
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
    [switch]$SkipBitLocker,

    [Parameter()]
    [switch]$SkipDebloat,

    [Parameter()]
    [switch]$RemoveOneDrive,

    [Parameter()]
    [switch]$RemoveDefaultApps,

    [Parameter()]
    [switch]$AggressiveDebloat,

    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\Logs\Workstation-Standalone-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"
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

# Helper function to create registry paths
function New-FolderForced {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Path
    )

    process {
        if (-not (Test-Path $Path)) {
            Write-Log "Creating folder: $Path" -Level "Info"
            try {
                $null = New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
            } catch {
                Write-Log "Cannot create folder: $Path" -Level "Warning"
            }
        }
    }
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
    Write-Log "Starting Workstation Standalone Setup" -Level "Info"
    Write-Log "========================================" -Level "Info"

    #region Windows Configuration
    Write-Log "Step 1: Configuring Windows Settings..." -Level "Info"
    try {
        # Enable registry backup
        New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Configuration Manager\' -Name 'EnablePeriodicBackup' -PropertyType DWORD -Value 0x00000001 -Force -ea 'SilentlyContinue'

        # Enable System Restore
        Enable-ComputerRestore -drive $Env:SYSTEMDRIVE'\'

        # Set power plan to High Performance
        powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

        Write-Log "Windows configuration completed" -Level "Info"
    } catch {
        Write-Log "Windows configuration error: $_" -Level "Warning"
    }
    #endregion

    #region User Profile Configuration
    Write-Log "Step 2: Configuring User Profiles..." -Level "Info"
    try {
        # Clear Start Menu
        $Url = 'https://s3.us-west-002.backblazeb2.com/public-dtc/repo/config/windows/start-menu-cleared.xml'
        wget $Url -OutFile $Env:WINDIR\temp\LayoutModification.xml -ErrorAction SilentlyContinue

        if (Test-Path $Env:WINDIR\temp\LayoutModification.xml) {
            Copy-Item $Env:WINDIR'\temp\LayoutModification.xml' -Destination $Env:LOCALAPPDATA'\Microsoft\Windows\Shell' -Force
            Copy-Item $Env:WINDIR'\temp\LayoutModification.xml' -Destination $Env:SYSTEMDRIVE'\Users\Default\AppData\Local\Microsoft\Windows\Shell' -Force
        }

        Write-Log "User profile configuration completed" -Level "Info"
    } catch {
        Write-Log "User profile configuration error: $_" -Level "Warning"
    }
    #endregion

    #region Deploy OEM Tools
    Write-Log "Step 3: Installing OEM Tools..." -Level "Info"
    try {
        $Manufacturer = Get-CimInstance -ClassName Win32_ComputerSystem | Select -ExpandProperty Manufacturer

        if ($Manufacturer -like "Dell*") {
            Write-Log "Dell hardware detected - installing Dell Command" -Level "Info"
            $progressPreference = 'SilentlyContinue'

            # Download latest Dell Command Update directly from Dell
            # DCU 5.3.0 - Latest version for Windows 11
            $dcuUrl = "https://dl.dell.com/FOLDER11866945M/1/Dell-Command-Update-Application_V1PM4_WIN_5.3.0_A00.EXE"

            # Dell SupportAssist for Business PCs
            $supportAssistUrl = "https://dl.dell.com/FOLDER11524920M/1/SupportAssistInstaller.exe"

            Write-Log "Downloading Dell Command Update..." -Level "Info"
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($dcuUrl, "$env:windir\temp\DCU_Setup.exe")

            Write-Log "Installing Dell Command Update..." -Level "Info"
            Start-Process -FilePath "$env:windir\temp\DCU_Setup.exe" -ArgumentList "/s" -Wait -NoNewWindow

            # Optional: Install SupportAssist
            Write-Log "Downloading Dell SupportAssist..." -Level "Info"
            $wc.DownloadFile($supportAssistUrl, "$env:windir\temp\SupportAssist_Setup.exe")

            Write-Log "Installing Dell SupportAssist..." -Level "Info"
            Start-Process -FilePath "$env:windir\temp\SupportAssist_Setup.exe" -ArgumentList "/quiet" -Wait -NoNewWindow

            Write-Log "Dell tools installation completed" -Level "Info"

            # Run Dell Command Update to check for driver updates
            Write-Log "Running Dell Command Update scan..." -Level "Info"
            if (Test-Path "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe") {
                Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/scan" -Wait -NoNewWindow
            }

        } else {
            Write-Log "Non-Dell hardware - skipping OEM tools" -Level "Info"
        }
        Write-Log "OEM tools installation completed" -Level "Info"
    } catch {
        Write-Log "OEM tools deployment error: $_" -Level "Warning"
    }
    #endregion

    #region Deploy Applications
    Write-Log "Step 4: Installing Applications..." -Level "Info"
    try {
        # Check if WinGet is available (Windows 11/Server 2025)
        $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
        if (!$wingetPath) {
            Write-Log "WinGet not found. Please ensure Windows 11 22H2 or later is installed." -Level "Error"
            throw "WinGet is required but not found"
        }

        # Install applications via WinGet
        $apps = @(
            @{id = "Mozilla.Firefox"; name = "Firefox"},
            @{id = "7zip.7zip"; name = "7-Zip"},
            @{id = "Microsoft.VisualStudioCode"; name = "Visual Studio Code"},
            @{id = "Microsoft.VCRedist.2015+.x64"; name = "Visual C++ Redistributable"},
            @{id = "Google.Chrome"; name = "Google Chrome"},
            @{id = "Adobe.Acrobat.Reader.64-bit"; name = "Adobe Reader"},
            @{id = "VideoLAN.VLC"; name = "VLC Media Player"},
            @{id = "Notepad++.Notepad++"; name = "Notepad++"},
            @{id = "Microsoft.PowerToys"; name = "PowerToys"},
            @{id = "Microsoft.WindowsTerminal"; name = "Windows Terminal"}
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

    #region Debloat Windows
    if (!$SkipDebloat) {
        Write-Log "Step 5: Running Windows Debloat..." -Level "Info"

        # Block Telemetry
        try {
            Write-Log "Blocking telemetry..." -Level "Info"

            # Disable telemetry via Group Policy
            New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0

            # Common telemetry domains to block
            $telemetryDomains = @(
                "telemetry.microsoft.com",
                "telemetry.urs.microsoft.com",
                "vortex.data.microsoft.com",
                "vortex-win.data.microsoft.com",
                "watson.telemetry.microsoft.com",
                "watson.microsoft.com",
                "feedback.windows.com",
                "feedback.microsoft-hohm.com",
                "feedback.search.microsoft.com",
                "dc.services.visualstudio.com",
                "services.wes.df.telemetry.microsoft.com"
            )

            $hosts_file = "$env:systemroot\System32\drivers\etc\hosts"
            Write-Output "" | Out-File -Encoding ASCII -Append $hosts_file
            foreach ($domain in $telemetryDomains) {
                if (-Not (Select-String -Path $hosts_file -Pattern $domain)) {
                    Write-Output "0.0.0.0 $domain" | Out-File -Encoding ASCII -Append $hosts_file
                }
            }

            Write-Log "Telemetry blocked" -Level "Info"
        } catch {
            Write-Log "Telemetry blocking error: $_" -Level "Warning"
        }

        # Disable unnecessary services
        try {
            Write-Log "Disabling unnecessary services..." -Level "Info"

            $services = @(
                "DiagTrack",                    # Connected User Experiences and Telemetry
                "dmwappushservice",             # Device Management WAP Push Service
                "HomeGroupListener",            # HomeGroup Listener
                "HomeGroupProvider",            # HomeGroup Provider
                "lfsvc",                        # Geolocation Service
                "MapsBroker",                   # Downloaded Maps Manager
                "NetTcpPortSharing",            # Net.Tcp Port Sharing Service
                "RemoteRegistry",               # Remote Registry
                "SharedAccess",                 # Internet Connection Sharing (ICS)
                "TrkWks",                       # Distributed Link Tracking Client
                "WbioSrvc",                     # Windows Biometric Service
                "WMPNetworkSvc",                # Windows Media Player Network Sharing Service
                "wscsvc",                       # Security Center
                "XblAuthManager",               # Xbox Live Auth Manager
                "XblGameSave",                  # Xbox Live Game Save
                "XboxNetApiSvc"                 # Xbox Live Networking Service
            )

            foreach ($service in $services) {
                Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
            }

            Write-Log "Unnecessary services disabled" -Level "Info"
        } catch {
            Write-Log "Service disabling error: $_" -Level "Warning"
        }

        # Fix privacy settings
        try {
            Write-Log "Fixing privacy settings..." -Level "Info"

            # Privacy: Let apps use advertising ID: Disable
            If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
                New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0

            # Privacy: SmartScreen Filter for Store Apps: Disable
            If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost")) {
                New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0

            # WiFi Sense: Shared HotSpot Auto-Connect: Disable
            If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
                New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Type DWord -Value 0

            Write-Log "Privacy settings fixed" -Level "Info"
        } catch {
            Write-Log "Privacy settings error: $_" -Level "Warning"
        }

        # Remove default apps (if specified)
        if ($RemoveDefaultApps) {
            Write-Log "Removing default Windows apps..." -Level "Info"
            try {
                $apps = @(
                    "Microsoft.3DBuilder",
                    "Microsoft.BingFinance",
                    "Microsoft.BingNews",
                    "Microsoft.BingSports",
                    "Microsoft.BingWeather",
                    "Microsoft.GetHelp",
                    "Microsoft.Getstarted",
                    "Microsoft.Messaging",
                    "Microsoft.Microsoft3DViewer",
                    "Microsoft.MicrosoftOfficeHub",
                    "Microsoft.MicrosoftSolitaireCollection",
                    "Microsoft.NetworkSpeedTest",
                    "Microsoft.News",
                    "Microsoft.Office.Lens",
                    "Microsoft.Office.OneNote",
                    "Microsoft.Office.Sway",
                    "Microsoft.OneConnect",
                    "Microsoft.People",
                    "Microsoft.Print3D",
                    "Microsoft.SkypeApp",
                    "Microsoft.Wallet",
                    "Microsoft.WindowsAlarms",
                    "Microsoft.WindowsFeedbackHub",
                    "Microsoft.WindowsMaps",
                    "Microsoft.WindowsSoundRecorder",
                    "Microsoft.Xbox.TCUI",
                    "Microsoft.XboxApp",
                    "Microsoft.XboxGameOverlay",
                    "Microsoft.XboxIdentityProvider",
                    "Microsoft.XboxSpeechToTextOverlay",
                    "Microsoft.ZuneMusic",
                    "Microsoft.ZuneVideo"
                )

                foreach ($app in $apps) {
                    Get-AppxPackage $app -AllUsers -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
                    Get-AppxProvisionedPackage -Online | Where DisplayName -like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
                }

                Write-Log "Default apps removed" -Level "Info"
            } catch {
                Write-Log "App removal error: $_" -Level "Warning"
            }
        }

        # Remove OneDrive (if specified)
        if ($RemoveOneDrive) {
            Write-Log "Removing OneDrive..." -Level "Info"
            try {
                # Stop OneDrive process
                Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
                Start-Sleep -s 3

                # Uninstall OneDrive
                $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
                If (!(Test-Path $onedrive)) {
                    $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
                }
                Start-Process $onedrive "/uninstall" -NoNewWindow -Wait

                # Remove OneDrive leftovers
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"

                # Disable OneDrive via Group Policies
                If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive")) {
                    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1

                Write-Log "OneDrive removed" -Level "Info"
            } catch {
                Write-Log "OneDrive removal error: $_" -Level "Warning"
            }
        }

        Write-Log "Debloat completed" -Level "Info"
    } else {
        Write-Log "Step 5: Skipping debloat (per parameter)" -Level "Info"
    }
    #endregion

    #region Performance Optimization
    Write-Log "Step 6: Applying performance optimizations..." -Level "Info"

    try {
        # Check for SSD and optimize
        $systemDrive = Get-PhysicalDisk | Where-Object {$_.MediaType -eq "SSD"}
        if ($systemDrive) {
            Write-Log "SSD detected, applying SSD optimizations..." -Level "Info"

            # Disable SysMain (Superfetch)
            Stop-Service "SysMain" -Force -ErrorAction SilentlyContinue
            Set-Service "SysMain" -StartupType Disabled

            # Disable Prefetch
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Type DWord -Value 0
        }

        # Disable unnecessary scheduled tasks
        $tasks = @(
            "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "\Microsoft\Windows\Autochk\Proxy",
            "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
            "\Microsoft\Windows\Maintenance\WinSAT",
            "\Microsoft\Windows\Shell\FamilySafetyUpload",
            "\Microsoft\Windows\SystemRestore\SR"
        )

        foreach ($task in $tasks) {
            Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        }

        # Disable Windows Search indexing for better performance (optional)
        if ($AggressiveDebloat) {
            Stop-Service "WSearch" -Force -ErrorAction SilentlyContinue
            Set-Service "WSearch" -StartupType Disabled
        }

        Write-Log "Performance optimizations completed" -Level "Info"
    } catch {
        Write-Log "Performance optimization error: $_" -Level "Warning"
    }
    #endregion

    #region Deploy Features
    Write-Log "Step 7: Installing Windows Features..." -Level "Info"
    try {
        # Install .NET Framework 3.5
        Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -ErrorAction SilentlyContinue

        # Install Windows Sandbox (if available)
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem
        if ($osInfo.Caption -match "Pro|Enterprise|Education") {
            Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All -ErrorAction SilentlyContinue
        }

        Write-Log "Windows features installed" -Level "Info"
    } catch {
        Write-Log "Feature installation error: $_" -Level "Warning"
    }
    #endregion

    #region BitLocker Configuration
    if (!$SkipBitLocker) {
        Write-Log "Step 8: Configuring BitLocker..." -Level "Info"
        try {
            # Check if TPM is present
            $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm
            if ($tpm) {
                # Enable BitLocker on OS drive
                $osDrive = Get-BitlockerVolume | Where -Property VolumeType -eq OperatingSystem
                if ($osDrive.ProtectionStatus -eq "Off") {
                    Enable-Bitlocker -MountPoint $osDrive.MountPoint -TpmProtector -EncryptionMethod AES256
                    Add-BitlockerKeyProtector -MountPoint $osDrive.MountPoint -RecoveryPasswordProtector
                }

                # Enable BitLocker on data drives
                $dataDrives = Get-BitlockerVolume | Where -Property VolumeType -ne OperatingSystem
                foreach ($drive in $dataDrives) {
                    if ($drive.ProtectionStatus -eq "Off") {
                        Enable-Bitlocker -MountPoint $drive.MountPoint -StartupKeyProtector -StartupKeyPath $Env:SYSTEMDRIVE\
                        Add-BitlockerKeyProtector -MountPoint $drive.MountPoint -RecoveryPasswordProtector
                        Enable-BitLockerAutoUnlock -MountPoint $drive.MountPoint
                    }
                }

                Write-Log "BitLocker configuration completed" -Level "Info"
            } else {
                Write-Log "No TPM detected, skipping BitLocker" -Level "Warning"
            }
        } catch {
            Write-Log "BitLocker configuration error: $_" -Level "Warning"
        }
    } else {
        Write-Log "Step 8: Skipping BitLocker configuration (per parameter)" -Level "Info"
    }
    #endregion

    #region Windows Updates
    if (!$SkipWindowsUpdate) {
        Write-Log "Step 9: Installing Windows Updates..." -Level "Info"
        try {
            Install-PackageProvider -Name NuGet -Force
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
            Install-Module PSWindowsUpdate -Force
            Get-WindowsUpdate -AcceptAll -Install -AutoReboot:$false
            Write-Log "Windows updates completed" -Level "Info"
        } catch {
            Write-Log "Windows Update error: $_" -Level "Warning"
        }
    } else {
        Write-Log "Step 9: Skipping Windows Updates (per parameter)" -Level "Info"
    }
    #endregion

    Write-Log "========================================" -Level "Info"
    Write-Log "Workstation Setup Complete!" -Level "Info"
    Write-Log "========================================" -Level "Info"
    Write-Log "" -Level "Info"
    Write-Log "Setup Summary:" -Level "Info"

    if (!$SkipDebloat) {
        Write-Log "✓ Telemetry blocked" -Level "Info"
        Write-Log "✓ Privacy settings optimized" -Level "Info"
        Write-Log "✓ Unnecessary services disabled" -Level "Info"
        if ($RemoveDefaultApps) {
            Write-Log "✓ Default Windows apps removed" -Level "Info"
        }
        if ($RemoveOneDrive) {
            Write-Log "✓ OneDrive removed" -Level "Info"
        }
    }

    if (!$SkipBitLocker) {
        Write-Log "✓ BitLocker configured (if supported)" -Level "Info"
    }

    Write-Log "✓ Performance optimizations applied" -Level "Info"
    Write-Log "✓ Essential applications installed" -Level "Info"

    Write-Log "" -Level "Info"
    Write-Log "Next Steps:" -Level "Info"
    Write-Log "1. Join to domain if required" -Level "Info"
    Write-Log "2. Configure user accounts" -Level "Info"
    Write-Log "3. Install user-specific applications" -Level "Info"
    Write-Log "4. Configure backup solutions" -Level "Info"
    Write-Log "5. Set up printers and peripherals" -Level "Info"
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