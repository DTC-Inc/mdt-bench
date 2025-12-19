<#
.SYNOPSIS
    Complete Standalone Workstation Setup Script - MSP RMM Template Version
.DESCRIPTION
    Single-file setup script for Windows workstations with all configurations,
    debloating, and optimizations. Follows MSP Script Library template for
    RMM deployment. Fully non-interactive when $RMM=1.
.NOTES
    Author: DTC Inc
    Version: 3.0 MSP Template
    Date: 2025-12-19

    RMM Variables:
    - $RMM: Set to 1 for RMM mode (no prompts)
    - $CompanyName: Company name for branding (default: DTC)
    - $SkipWindowsUpdate: Skip Windows Updates (default: false)
    - $SkipBitLocker: Skip BitLocker configuration (default: false)
    - $SkipDebloat: Skip all debloat operations (default: false)
    - $RemoveOneDrive: Completely remove OneDrive (default: false)
    - $RemoveDefaultApps: Remove Windows default apps (default: false)
    - $AggressiveDebloat: Maximum optimization (default: false)
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

## SECTION 1: RMM VARIABLE DECLARATION
## PLEASE COMMENT YOUR VARIABLES DIRECTLY BELOW HERE IF YOU'RE RUNNING FROM A RMM
## $RMM = 1
## $CompanyName = "DTC"
## $SkipWindowsUpdate = $false
## $SkipBitLocker = $false
## $SkipDebloat = $false
## $RemoveOneDrive = $false
## $RemoveDefaultApps = $false
## $AggressiveDebloat = $false

## SECTION 2: INPUT HANDLING
# Initialize variables with defaults if not set
if ($null -eq $CompanyName) { $CompanyName = "DTC" }
if ($null -eq $SkipWindowsUpdate) { $SkipWindowsUpdate = $false }
if ($null -eq $SkipBitLocker) { $SkipBitLocker = $false }
if ($null -eq $SkipDebloat) { $SkipDebloat = $false }
if ($null -eq $RemoveOneDrive) { $RemoveOneDrive = $false }
if ($null -eq $RemoveDefaultApps) { $RemoveDefaultApps = $false }
if ($null -eq $AggressiveDebloat) { $AggressiveDebloat = $false }

# Script name for logging
$ScriptLogName = "Workstation-Setup-v3"

# Detect RMM mode
if ($RMM -ne 1) {
    # Interactive mode - prompt for options
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Workstation Setup Script (v3)" -ForegroundColor Cyan
    Write-Host "Interactive Mode" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Computer Name: $env:COMPUTERNAME" -ForegroundColor Green
    Write-Host "(Workstations retain existing names)" -ForegroundColor Gray
    Write-Host ""

    # Get company name
    $input = Read-Host "Enter company name (default: DTC)"
    if (![string]::IsNullOrEmpty($input)) { $CompanyName = $input }

    # Ask about debloat options
    $response = Read-Host "Remove Windows default apps? (y/n, default: n)"
    if ($response -eq 'y') { $RemoveDefaultApps = $true }

    $response = Read-Host "Remove OneDrive completely? (y/n, default: n)"
    if ($response -eq 'y') { $RemoveOneDrive = $true }

    $response = Read-Host "Apply aggressive debloat (maximum optimization)? (y/n, default: n)"
    if ($response -eq 'y') { $AggressiveDebloat = $true }

    $response = Read-Host "Skip all debloat operations? (y/n, default: n)"
    if ($response -eq 'y') { $SkipDebloat = $true }

    # Ask about updates
    $response = Read-Host "Skip Windows Updates? (y/n, default: n)"
    if ($response -eq 'y') { $SkipWindowsUpdate = $true }

    # Ask about BitLocker
    $response = Read-Host "Skip BitLocker configuration? (y/n, default: n)"
    if ($response -eq 'y') { $SkipBitLocker = $true }

    $Description = Read-Host "Enter a description for this setup (optional)"
    if ([string]::IsNullOrEmpty($Description)) {
        $Description = "Workstation setup for $CompanyName"
    }

    # Set log path for interactive mode
    $LogPath = "$ENV:WINDIR\logs"
} else {
    # RMM mode - use variables passed from RMM
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Workstation Setup Script (v3)" -ForegroundColor Cyan
    Write-Host "RMM Mode - Non-Interactive" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Computer Name: $env:COMPUTERNAME" -ForegroundColor Green
    Write-Host "(Workstations retain existing names)" -ForegroundColor Gray

    $Description = "RMM-initiated workstation setup for $CompanyName"

    # Set log path for RMM mode
    if ($null -ne $RMMScriptPath -and $RMMScriptPath -ne "") {
        $LogPath = "$RMMScriptPath\logs"
    } else {
        $LogPath = "$ENV:WINDIR\logs"
    }
}

# Ensure log directory exists
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$LogFile = Join-Path $LogPath "$ScriptLogName-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"

# Helper function to create registry paths
function New-FolderForced {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Path
    )

    process {
        if (-not (Test-Path $Path)) {
            try {
                $null = New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
            } catch {
                Write-Host "Cannot create folder: $Path" -ForegroundColor Yellow
            }
        }
    }
}

## SECTION 3: MAIN SCRIPT LOGIC
Start-Transcript -Path $LogFile

Write-Host "========================================" -ForegroundColor Green
Write-Host "Starting $ScriptLogName" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Description: $Description"
Write-Host "Log Path: $LogFile"
Write-Host "RMM Mode: $(if ($RMM -eq 1) { 'Yes' } else { 'No' })"
Write-Host "Company Name: $CompanyName"
Write-Host ""
Write-Host "Configuration Options:" -ForegroundColor Yellow
Write-Host "  Skip Debloat: $SkipDebloat"
Write-Host "  Remove Default Apps: $RemoveDefaultApps"
Write-Host "  Remove OneDrive: $RemoveOneDrive"
Write-Host "  Aggressive Debloat: $AggressiveDebloat"
Write-Host "  Skip Windows Update: $SkipWindowsUpdate"
Write-Host "  Skip BitLocker: $SkipBitLocker"
Write-Host ""

# Error handling
$ErrorActionPreference = "Stop"
$RestartRequired = $false

try {
    #region Windows Configuration
    Write-Host "Step 1: Configuring Windows Settings..." -ForegroundColor Cyan
    try {
        # Enable registry backup
        New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Configuration Manager\' `
                        -Name 'EnablePeriodicBackup' -PropertyType DWORD -Value 0x00000001 -Force -ErrorAction SilentlyContinue | Out-Null

        # Enable System Restore
        Enable-ComputerRestore -Drive "$env:SYSTEMDRIVE\"

        # Set power plan to High Performance
        powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

        Write-Host "Windows configuration completed" -ForegroundColor Green
    } catch {
        Write-Host "Windows configuration error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region User Profile Configuration
    Write-Host ""
    Write-Host "Step 2: Configuring User Profiles..." -ForegroundColor Cyan
    try {
        # Clear Start Menu
        $Url = 'https://s3.us-west-002.backblazeb2.com/public-dtc/repo/config/windows/start-menu-cleared.xml'
        $outFile = "$env:WINDIR\temp\LayoutModification.xml"

        try {
            Invoke-WebRequest -Uri $Url -OutFile $outFile -UseBasicParsing
        } catch {
            Write-Host "Could not download start menu layout" -ForegroundColor Yellow
        }

        if (Test-Path $outFile) {
            Copy-Item $outFile -Destination "$env:LOCALAPPDATA\Microsoft\Windows\Shell" -Force
            Copy-Item $outFile -Destination "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell" -Force
            Write-Host "Start menu layout configured" -ForegroundColor Green
        }
    } catch {
        Write-Host "User profile configuration error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Deploy OEM Tools
    Write-Host ""
    Write-Host "Step 3: Installing OEM Tools..." -ForegroundColor Cyan
    try {
        $Manufacturer = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer

        if ($Manufacturer -like "Dell*") {
            Write-Host "Dell hardware detected - installing Dell Command"

            # Download URLs for Dell tools
            $dcuUrl = "https://dl.dell.com/FOLDER11866945M/1/Dell-Command-Update-Application_V1PM4_WIN_5.3.0_A00.EXE"
            $supportAssistUrl = "https://dl.dell.com/FOLDER11524920M/1/SupportAssistInstaller.exe"

            # Download and install Dell Command Update
            Write-Host "Downloading Dell Command Update..."
            Invoke-WebRequest -Uri $dcuUrl -OutFile "$env:WINDIR\temp\DCU_Setup.exe" -UseBasicParsing
            Write-Host "Installing Dell Command Update..."
            Start-Process -FilePath "$env:WINDIR\temp\DCU_Setup.exe" -ArgumentList "/s" -Wait -NoNewWindow

            # Download and install SupportAssist
            Write-Host "Downloading Dell SupportAssist..."
            Invoke-WebRequest -Uri $supportAssistUrl -OutFile "$env:WINDIR\temp\SupportAssist_Setup.exe" -UseBasicParsing
            Write-Host "Installing Dell SupportAssist..."
            Start-Process -FilePath "$env:WINDIR\temp\SupportAssist_Setup.exe" -ArgumentList "/quiet" -Wait -NoNewWindow

            Write-Host "Dell tools installed" -ForegroundColor Green

            # Run Dell Command Update scan
            if (Test-Path "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe") {
                Write-Host "Running Dell Command Update scan..."
                Start-Process -FilePath "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/scan" -Wait -NoNewWindow
            }
        } else {
            Write-Host "Non-Dell hardware - skipping OEM tools"
        }
    } catch {
        Write-Host "OEM tools deployment error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Deploy Applications
    Write-Host ""
    Write-Host "Step 4: Installing Applications..." -ForegroundColor Cyan
    try {
        # Check if WinGet is available
        $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
        if ($wingetPath) {
            # Install essential applications
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
                Write-Host "Installing $($app.name)..."
                winget install --id $app.id --exact --silent --accept-package-agreements --accept-source-agreements
            }

            Write-Host "Applications installed" -ForegroundColor Green
        } else {
            Write-Host "WinGet not available - skipping application installation" -ForegroundColor Yellow
            Write-Host "Please ensure Windows 11 22H2 or later is installed" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Application deployment error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Debloat Windows
    if (!$SkipDebloat) {
        Write-Host ""
        Write-Host "Step 5: Running Windows Debloat..." -ForegroundColor Cyan

        # Block Telemetry
        try {
            Write-Host "Blocking telemetry..."

            # Disable telemetry via Group Policy
            New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

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

            $hosts_file = "$env:SYSTEMROOT\System32\drivers\etc\hosts"
            Write-Output "" | Out-File -Encoding ASCII -Append $hosts_file
            foreach ($domain in $telemetryDomains) {
                if (-Not (Select-String -Path $hosts_file -Pattern $domain -ErrorAction SilentlyContinue)) {
                    Write-Output "0.0.0.0 $domain" | Out-File -Encoding ASCII -Append $hosts_file
                }
            }

            Write-Host "Telemetry blocked" -ForegroundColor Green
        } catch {
            Write-Host "Telemetry blocking error: $_" -ForegroundColor Yellow
        }

        # Disable unnecessary services
        try {
            Write-Host "Disabling unnecessary services..."

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
                "WbioSrvc",                     # Windows Biometric Service (unless needed)
                "WMPNetworkSvc",                # Windows Media Player Network Sharing Service
                "XblAuthManager",               # Xbox Live Auth Manager
                "XblGameSave",                  # Xbox Live Game Save
                "XboxNetApiSvc"                 # Xbox Live Networking Service
            )

            foreach ($service in $services) {
                Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
            }

            Write-Host "Unnecessary services disabled" -ForegroundColor Green
        } catch {
            Write-Host "Service disabling error: $_" -ForegroundColor Yellow
        }

        # Fix privacy settings
        try {
            Write-Host "Fixing privacy settings..."

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

            Write-Host "Privacy settings fixed" -ForegroundColor Green
        } catch {
            Write-Host "Privacy settings error: $_" -ForegroundColor Yellow
        }

        # Remove default apps (if specified)
        if ($RemoveDefaultApps) {
            Write-Host "Removing default Windows apps..."
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
                    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                        Where-Object DisplayName -like $app |
                        Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
                }

                Write-Host "Default apps removed" -ForegroundColor Green
            } catch {
                Write-Host "App removal error: $_" -ForegroundColor Yellow
            }
        }

        # Remove OneDrive (if specified)
        if ($RemoveOneDrive) {
            Write-Host "Removing OneDrive..."
            try {
                # Stop OneDrive process
                Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3

                # Uninstall OneDrive
                $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
                If (!(Test-Path $onedrive)) {
                    $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
                }
                if (Test-Path $onedrive) {
                    Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
                }

                # Remove OneDrive leftovers
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:LOCALAPPDATA\Microsoft\OneDrive"
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:PROGRAMDATA\Microsoft OneDrive"
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:SYSTEMDRIVE\OneDriveTemp"

                # Disable OneDrive via Group Policies
                If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive")) {
                    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1

                Write-Host "OneDrive removed" -ForegroundColor Green
            } catch {
                Write-Host "OneDrive removal error: $_" -ForegroundColor Yellow
            }
        }

        Write-Host "Debloat completed" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "Step 5: Skipping debloat" -ForegroundColor Gray
    }
    #endregion

    #region Performance Optimization
    Write-Host ""
    Write-Host "Step 6: Applying performance optimizations..." -ForegroundColor Cyan

    try {
        # Check for SSD and optimize
        $systemDrive = Get-PhysicalDisk | Where-Object { $_.MediaType -eq "SSD" }
        if ($systemDrive) {
            Write-Host "SSD detected, applying SSD optimizations..."

            # Disable SysMain (Superfetch)
            Stop-Service "SysMain" -Force -ErrorAction SilentlyContinue
            Set-Service "SysMain" -StartupType Disabled

            # Disable Prefetch
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" `
                           -Name "EnablePrefetcher" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" `
                           -Name "EnableSuperfetch" -Type DWord -Value 0
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
            "\Microsoft\Windows\Shell\FamilySafetyUpload"
        )

        foreach ($task in $tasks) {
            Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        }

        # Disable Windows Search indexing for better performance (if aggressive)
        if ($AggressiveDebloat) {
            Stop-Service "WSearch" -Force -ErrorAction SilentlyContinue
            Set-Service "WSearch" -StartupType Disabled
            Write-Host "Windows Search disabled (aggressive optimization)" -ForegroundColor Yellow
        }

        Write-Host "Performance optimizations completed" -ForegroundColor Green
    } catch {
        Write-Host "Performance optimization error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Deploy Features
    Write-Host ""
    Write-Host "Step 7: Installing Windows Features..." -ForegroundColor Cyan
    try {
        # Install .NET Framework 3.5
        Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -NoRestart -ErrorAction SilentlyContinue | Out-Null

        # Install Windows Sandbox (if available)
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem
        if ($osInfo.Caption -match "Pro|Enterprise|Education") {
            Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Write-Host "Windows Sandbox enabled (if supported)" -ForegroundColor Green
        }

        Write-Host "Windows features installed" -ForegroundColor Green
    } catch {
        Write-Host "Feature installation error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region BitLocker Configuration
    if (!$SkipBitLocker) {
        Write-Host ""
        Write-Host "Step 8: Configuring BitLocker..." -ForegroundColor Cyan
        try {
            # Check if TPM is present
            $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
            if ($tpm) {
                # Enable BitLocker on OS drive
                $osDrive = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq "OperatingSystem" }
                if ($osDrive.ProtectionStatus -eq "Off") {
                    Enable-BitLocker -MountPoint $osDrive.MountPoint -TpmProtector -EncryptionMethod AES256
                    Add-BitLockerKeyProtector -MountPoint $osDrive.MountPoint -RecoveryPasswordProtector
                    Write-Host "BitLocker enabled on OS drive" -ForegroundColor Green
                }

                # Enable BitLocker on data drives
                $dataDrives = Get-BitLockerVolume | Where-Object { $_.VolumeType -ne "OperatingSystem" }
                foreach ($drive in $dataDrives) {
                    if ($drive.ProtectionStatus -eq "Off") {
                        Enable-BitLocker -MountPoint $drive.MountPoint -StartupKeyProtector -StartupKeyPath "$env:SYSTEMDRIVE\"
                        Add-BitLockerKeyProtector -MountPoint $drive.MountPoint -RecoveryPasswordProtector
                        Enable-BitLockerAutoUnlock -MountPoint $drive.MountPoint
                        Write-Host "BitLocker enabled on $($drive.MountPoint) drive" -ForegroundColor Green
                    }
                }
            } else {
                Write-Host "No TPM detected, skipping BitLocker" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "BitLocker configuration error: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host ""
        Write-Host "Step 8: Skipping BitLocker configuration" -ForegroundColor Gray
    }
    #endregion

    #region Windows Updates
    if (!$SkipWindowsUpdate) {
        Write-Host ""
        Write-Host "Step 9: Installing Windows Updates..." -ForegroundColor Cyan
        try {
            Install-PackageProvider -Name NuGet -Force -Confirm:$false | Out-Null
            Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
            Install-Module PSWindowsUpdate -Force -Confirm:$false | Out-Null
            Import-Module PSWindowsUpdate

            Write-Host "Checking for updates..."
            $updates = Get-WindowsUpdate
            if ($updates) {
                Write-Host "Installing $($updates.Count) updates..."
                Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot | Out-Null
                Write-Host "Windows updates completed" -ForegroundColor Green
                $RestartRequired = $true
            } else {
                Write-Host "No updates available"
            }
        } catch {
            Write-Host "Windows Update error: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host ""
        Write-Host "Step 9: Skipping Windows Updates" -ForegroundColor Gray
    }
    #endregion

    # Setup Complete
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Workstation Setup Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Computer Configuration:" -ForegroundColor Cyan
    Write-Host "  Name: $env:COMPUTERNAME"
    Write-Host "  Company: $CompanyName"
    Write-Host ""

    if (!$SkipDebloat) {
        Write-Host "Debloat Results:" -ForegroundColor Cyan
        Write-Host "  ✓ Telemetry blocked" -ForegroundColor Green
        Write-Host "  ✓ Privacy settings optimized" -ForegroundColor Green
        Write-Host "  ✓ Unnecessary services disabled" -ForegroundColor Green
        if ($RemoveDefaultApps) {
            Write-Host "  ✓ Default Windows apps removed" -ForegroundColor Green
        }
        if ($RemoveOneDrive) {
            Write-Host "  ✓ OneDrive removed" -ForegroundColor Green
        }
        Write-Host ""
    }

    Write-Host "Optimizations Applied:" -ForegroundColor Cyan
    Write-Host "  ✓ Performance optimizations" -ForegroundColor Green
    Write-Host "  ✓ Essential applications installed" -ForegroundColor Green
    if (!$SkipBitLocker) {
        Write-Host "  ✓ BitLocker configured (if supported)" -ForegroundColor Green
    }
    Write-Host ""

    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Join to domain if required"
    Write-Host "  2. Configure user accounts"
    Write-Host "  3. Install user-specific applications"
    Write-Host "  4. Configure backup solutions"
    Write-Host "  5. Set up printers and peripherals"
    Write-Host ""
    Write-Host "Log file: $LogFile"

    # Handle restart
    if ($RestartRequired) {
        Write-Host ""
        Write-Host "RESTART REQUIRED" -ForegroundColor Yellow

        if ($RMM -eq 1) {
            Write-Host "RMM Mode: Automatic restart in 60 seconds..." -ForegroundColor Yellow
            Write-Host "Run 'shutdown /a' to cancel" -ForegroundColor Yellow
            shutdown /r /t 60 /c "Workstation setup complete. Restarting in 60 seconds..."
        } else {
            $response = Read-Host "Restart now? (y/n)"
            if ($response -eq 'y') {
                Write-Host "Restarting computer..."
                Restart-Computer -Force
            } else {
                Write-Host "Please restart manually to apply all changes" -ForegroundColor Yellow
            }
        }
    } else {
        if ($RMM -ne 1) {
            $response = Read-Host "Setup complete. Restart recommended. Restart now? (y/n)"
            if ($response -eq 'y') {
                Write-Host "Restarting computer..."
                Restart-Computer -Force
            }
        }
    }

} catch {
    Write-Host ""
    Write-Host "ERROR: Setup failed!" -ForegroundColor Red
    Write-Host "Error details: $_" -ForegroundColor Red
    Write-Host "Please review the log file: $LogFile" -ForegroundColor Yellow
    exit 1
} finally {
    Stop-Transcript
}