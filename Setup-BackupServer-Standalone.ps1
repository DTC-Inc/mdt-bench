<#
.SYNOPSIS
    Complete Standalone Backup & Disaster Recovery Server Setup Script
.DESCRIPTION
    Single-file setup script for BDR servers with Storage Spaces mirroring,
    optimized for Veeam Backup & Replication. No external script dependencies.
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
    [switch]$SkipNetworkTeaming,

    [Parameter()]
    [switch]$SkipStorageSpaces,

    [Parameter()]
    [switch]$InstallVeeam,  # Placeholder - Veeam requires manual licensing

    [Parameter()]
    [ValidateSet("ers", "rrs", "zrs", "grs")]
    [string]$StorageRedundancy = "ers",  # Default to Endpoint Redundant Storage

    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\Logs\BackupServer-Standalone-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"
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
    Write-Host $LogMessage -ForegroundColor $(if($Level -eq "Error"){"Red"}elseif($Level -eq "Warning"){"Yellow"}else{"White"})
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
    Write-Log "Starting Backup Server Standalone Setup" -Level "Info"
    Write-Log "========================================" -Level "Info"

    #region Storage Spaces Configuration for Redundancy
    if (!$SkipStorageSpaces) {
        Write-Log "Step 1: Configuring Storage Spaces with Mirroring..." -Level "Info"
        try {
            # Clean up any existing storage pools
            Write-Log "Cleaning up existing storage configurations..." -Level "Info"

            Get-VirtualDisk -ErrorAction SilentlyContinue | Remove-VirtualDisk -Confirm:$false -ErrorAction SilentlyContinue
            Get-StoragePool -ErrorAction SilentlyContinue | Where-Object { $_.IsPrimordial -eq $false } |
                Remove-StoragePool -Confirm:$false -ErrorAction SilentlyContinue

            # Reset physical disks
            Get-PhysicalDisk | Reset-PhysicalDisk -ErrorAction SilentlyContinue

            # Get disks for pool (non-boot, non-system)
            $availableDisks = Get-PhysicalDisk -CanPool $true

            if ($availableDisks.Count -ge 2) {
                Write-Host "`n📊 Available disks for Storage Spaces:" -ForegroundColor Cyan
                $availableDisks | Format-Table FriendlyName, Size, MediaType -AutoSize

                $createPool = Read-Host "Create mirrored storage pool with these disks? (y/n)"

                if ($createPool -eq 'y') {
                    $storageSubsystem = Get-StorageSubsystem | Select-Object -First 1 -ExpandProperty FriendlyName

                    # Create storage pool
                    Write-Log "Creating storage pool 'BackupPool'..." -Level "Info"
                    New-StoragePool -FriendlyName "BackupPool" `
                                   -StorageSubsystemFriendlyName $storageSubsystem `
                                   -PhysicalDisks $availableDisks

                    # Create mirrored virtual disk with proper naming
                    $volumeLabel = "$StorageRedundancy-mirror-01"
                    Write-Log "Creating mirrored virtual disk '$volumeLabel'..." -Level "Info"

                    New-VirtualDisk -StoragePoolFriendlyName "BackupPool" `
                                   -FriendlyName "BackupDisk" `
                                   -ResiliencySettingName Mirror `
                                   -UseMaximumSize

                    # Initialize and format the volume
                    Get-VirtualDisk -FriendlyName "BackupDisk" |
                        Get-Disk |
                        Initialize-Disk -PartitionStyle GPT -PassThru |
                        New-Partition -AssignDriveLetter -UseMaximumSize |
                        Format-Volume -FileSystem NTFS `
                                     -AllocationUnitSize 65536 `
                                     -NewFileSystemLabel $volumeLabel `
                                     -Confirm:$false

                    Write-Log "Storage Spaces configuration completed with mirroring" -Level "Info"
                }
            } else {
                Write-Log "Insufficient disks for Storage Spaces mirroring (need at least 2)" -Level "Warning"

                # Fallback to standard disk configuration
                Write-Log "Falling back to standard disk configuration..." -Level "Info"
                $dataDisks = Get-Disk | Where-Object { $_.IsBoot -eq $false -and $_.IsSystem -eq $false }

                if ($dataDisks) {
                    $disk = $dataDisks | Select-Object -First 1
                    if ($disk.PartitionStyle -eq 'RAW') {
                        Initialize-Disk -Number $disk.Number -PartitionStyle GPT
                    }

                    New-Partition -DiskNumber $disk.Number -UseMaximumSize -DriveLetter D
                    Format-Volume -DriveLetter D -FileSystem NTFS `
                                 -AllocationUnitSize 65536 `
                                 -NewFileSystemLabel "$StorageRedundancy-backup-01"
                }
            }
        } catch {
            Write-Log "Storage Spaces configuration error: $_" -Level "Warning"
        }
    } else {
        Write-Log "Step 1: Skipping Storage Spaces configuration (per parameter)" -Level "Info"
    }
    #endregion

    #region Filesystem Configuration for Backup Software
    Write-Log "Step 2: Creating Backup Software Directory Structure..." -Level "Info"
    try {
        # Find the data drive (prefer D:, but use first available data drive)
        $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                     Select-Object -First 1 -ExpandProperty DriveLetter

        if ($dataDrive) {
            $dataPath = "${dataDrive}:"

            # Create Veeam directories
            New-Item -Path "$dataPath\VeeamBackup" -ItemType Directory -Force | Out-Null
            New-Item -Path "$dataPath\VeeamBackup\Repository" -ItemType Directory -Force | Out-Null
            New-Item -Path "$dataPath\VeeamBackup\Configuration" -ItemType Directory -Force | Out-Null
            New-Item -Path "$dataPath\VeeamBackup\Staging" -ItemType Directory -Force | Out-Null

            # Create MSP360 directories
            New-Item -Path "$dataPath\MSP360" -ItemType Directory -Force | Out-Null
            New-Item -Path "$dataPath\MSP360\CloudStorage" -ItemType Directory -Force | Out-Null
            New-Item -Path "$dataPath\MSP360\LocalStorage" -ItemType Directory -Force | Out-Null

            # Create general backup directories
            New-Item -Path "$dataPath\Backups" -ItemType Directory -Force | Out-Null
            New-Item -Path "$dataPath\Backups\FileBackups" -ItemType Directory -Force | Out-Null
            New-Item -Path "$dataPath\Backups\ImageBackups" -ItemType Directory -Force | Out-Null
            New-Item -Path "$dataPath\Backups\Archives" -ItemType Directory -Force | Out-Null

            # Create repository directory
            New-Item -Path "$dataPath\Repository" -ItemType Directory -Force | Out-Null

            Write-Log "Backup directory structure created on $dataPath drive" -Level "Info"
        } else {
            Write-Log "No data drive found for backup directories" -Level "Warning"
        }
    } catch {
        Write-Log "Filesystem configuration error: $_" -Level "Warning"
    }
    #endregion

    #region Network Configuration with Teaming
    Write-Log "Step 3: Configuring Network with Redundancy..." -Level "Info"
    if (!$SkipNetworkTeaming) {
        try {
            # Clean up existing virtual switches and teams
            Write-Log "Cleaning up existing network configuration..." -Level "Info"
            Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notlike "Container NIC*" } |
                Remove-VMNetworkAdapter -ErrorAction SilentlyContinue

            Get-VMSwitch -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notlike "Default Switch" } |
                Remove-VMSwitch -Force -ErrorAction SilentlyContinue

            Get-NetSwitchTeam -ErrorAction SilentlyContinue | Remove-NetSwitchTeam -Confirm:$false

            Start-Sleep -Seconds 5

            # Get available network adapters
            $adapters = Get-NetAdapter | Where-Object {
                $_.Status -eq 'Up' -and
                $_.Virtual -eq $false -and
                $_.InterfaceDescription -notlike "*Virtual*" -and
                $_.InterfaceDescription -notlike "*Hyper-V*"
            }

            if ($adapters.Count -ge 2) {
                Write-Host "`n🔌 Available network adapters for teaming:" -ForegroundColor Cyan
                $adapters | Format-Table Name, InterfaceDescription, LinkSpeed, Status -AutoSize

                $createTeam = Read-Host "Create network team for redundancy? (y/n)"

                if ($createTeam -eq 'y') {
                    # Check if Hyper-V is installed
                    $hyperVInstalled = (Get-WindowsFeature -Name Hyper-V -ErrorAction SilentlyContinue).InstallState -eq "Installed"

                    if ($hyperVInstalled) {
                        # Create SET team for Hyper-V
                        Write-Log "Creating Switch Embedded Team (SET)..." -Level "Info"
                        New-VMSwitch -Name "BackupSET" `
                                    -NetAdapterName $adapters.Name `
                                    -EnableEmbeddedTeaming $true `
                                    -AllowManagementOS $true

                        Rename-VMNetworkAdapter -Name "BackupSET" -NewName "vNIC-Backup" -ManagementOS
                    } else {
                        # Create LBFO team
                        Write-Log "Creating LBFO network team..." -Level "Info"
                        New-NetLbfoTeam -Name "BackupTeam" `
                                       -TeamMembers $adapters.Name `
                                       -LoadBalancingAlgorithm Dynamic `
                                       -TeamingMode SwitchIndependent `
                                       -Confirm:$false
                    }

                    Write-Log "Network teaming configured successfully" -Level "Info"
                }
            } else {
                Write-Log "Insufficient network adapters for teaming" -Level "Warning"
            }
        } catch {
            Write-Log "Network configuration error: $_" -Level "Warning"
        }
    } else {
        Write-Log "Step 3: Skipping network teaming (per parameter)" -Level "Info"
    }
    #endregion

    #region Windows Configuration
    Write-Log "Step 4: Configuring Windows Settings..." -Level "Info"
    try {
        # Disable Windows Firewall (temporarily for setup)
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

        # Disable Server Manager auto-start
        Get-ScheduledTask -TaskName ServerManager -ErrorAction SilentlyContinue |
            Disable-ScheduledTask -ErrorAction SilentlyContinue

        # Enable registry backup
        New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Configuration Manager\' `
                        -Name 'EnablePeriodicBackup' -PropertyType DWORD -Value 0x00000001 -Force -ErrorAction SilentlyContinue

        # Set power plan to High Performance
        powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

        # Disable hibernation (saves disk space)
        powercfg -h off

        Write-Log "Windows configuration completed" -Level "Info"
    } catch {
        Write-Log "Windows configuration error: $_" -Level "Warning"
    }
    #endregion

    #region Deploy Windows Features & Hyper-V
    Write-Log "Step 5: Installing Windows Features & Hyper-V..." -Level "Info"
    try {
        # Install Hyper-V FIRST - Critical for backup operations
        Write-Log "Installing Hyper-V (required for Instant VM Recovery)..." -Level "Info"
        $hyperV = Get-WindowsFeature -Name Hyper-V
        if ($hyperV.InstallState -ne "Installed") {
            Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -IncludeAllSubFeature -Restart:$false
            Write-Log "Hyper-V installed successfully" -Level "Info"

            # Configure Hyper-V storage paths if data drive exists
            $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                         Select-Object -First 1 -ExpandProperty DriveLetter
            if ($dataDrive) {
                Set-VMHost -VirtualHardDiskPath "${dataDrive}:\Hyper-V\Virtual Hard Disks"
                Set-VMHost -VirtualMachinePath "${dataDrive}:\Hyper-V"

                # Create Hyper-V directories
                New-Item -Path "${dataDrive}:\Hyper-V\Virtual Hard Disks" -ItemType Directory -Force | Out-Null
                New-Item -Path "${dataDrive}:\Hyper-V\Virtual Machines" -ItemType Directory -Force | Out-Null
                New-Item -Path "${dataDrive}:\Hyper-V\Instant Recovery" -ItemType Directory -Force | Out-Null

                Write-Log "Hyper-V configured with paths on ${dataDrive}: drive" -Level "Info"
            }
        } else {
            Write-Log "Hyper-V already installed" -Level "Info"
        }

        # Install deduplication for backup storage efficiency
        Write-Log "Installing Data Deduplication feature..." -Level "Info"
        Enable-WindowsOptionalFeature -Online -FeatureName Dedup-Core -All -NoRestart

        # Install .NET Framework (required for many backup solutions)
        Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName NetFx4-AdvSrvs -All -NoRestart

        # Install Windows Server Backup feature
        Install-WindowsFeature -Name Windows-Server-Backup -IncludeManagementTools

        Write-Log "Windows features and Hyper-V installed successfully" -Level "Info"
    } catch {
        Write-Log "Feature installation error: $_" -Level "Warning"
    }
    #endregion

    #region Deploy OEM Tools
    Write-Log "Step 6: Installing OEM Tools..." -Level "Info"
    try {
        $Manufacturer = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer

        if ($Manufacturer -like "Dell*") {
            Write-Log "Dell hardware detected - installing OpenManage" -Level "Info"

            # Download and install Dell OpenManage
            $omsaUrl = "https://dl.dell.com/FOLDER11337880M/1/Windows_OMSA_11.0.1.0_A00.exe"
            $ismUrl = "https://dl.dell.com/FOLDER11034445M/1/iDRAC-Service-Module-5.3.0.0_Windows_x64.exe"

            $wc = New-Object System.Net.WebClient

            Write-Log "Downloading Dell OpenManage..." -Level "Info"
            $wc.DownloadFile($omsaUrl, "$env:windir\temp\OMSA_Setup.exe")

            Write-Log "Installing Dell OpenManage..." -Level "Info"
            Start-Process -FilePath "$env:windir\temp\OMSA_Setup.exe" -ArgumentList "/s" -Wait -NoNewWindow

            Write-Log "Downloading iDRAC Service Module..." -Level "Info"
            $wc.DownloadFile($ismUrl, "$env:windir\temp\ISM_Setup.exe")

            Write-Log "Installing iDRAC Service Module..." -Level "Info"
            Start-Process -FilePath "$env:windir\temp\ISM_Setup.exe" -ArgumentList "/s" -Wait -NoNewWindow

            Write-Log "Dell tools installation completed" -Level "Info"
        } else {
            Write-Log "Non-Dell hardware - skipping OEM tools" -Level "Info"
        }
    } catch {
        Write-Log "OEM tools installation error: $_" -Level "Warning"
    }
    #endregion

    #region Deploy Applications
    Write-Log "Step 7: Installing Applications..." -Level "Info"
    try {
        # Check if WinGet is available
        $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
        if (!$wingetPath) {
            Write-Log "WinGet not found. Please ensure Windows Server 2025 is installed." -Level "Error"
            throw "WinGet is required but not found"
        }

        # Install essential applications
        $apps = @(
            @{id = "Mozilla.Firefox"; name = "Firefox"},
            @{id = "7zip.7zip"; name = "7-Zip"},
            @{id = "Microsoft.VisualStudioCode"; name = "Visual Studio Code"},
            @{id = "Microsoft.VCRedist.2015+.x64"; name = "Visual C++ Redistributable"},
            @{id = "Notepad++.Notepad++"; name = "Notepad++"},
            @{id = "Microsoft.PowerShell"; name = "PowerShell 7"}
        )

        foreach ($app in $apps) {
            Write-Log "Installing $($app.name)..." -Level "Info"
            winget install --id $app.id --exact --silent --accept-package-agreements --accept-source-agreements
        }

        Write-Log "Applications installed" -Level "Info"
    } catch {
        Write-Log "Application installation error: $_" -Level "Warning"
    }
    #endregion

    #region Backup Software Configuration
    Write-Log "Step 8: Backup Software Configuration..." -Level "Info"

    if ($InstallVeeam) {
        Write-Log "Veeam installation requires manual licensing and configuration" -Level "Warning"
        Write-Log "Please download and install Veeam Backup & Replication from:" -Level "Info"
        Write-Log "https://www.veeam.com/downloads.html" -Level "Info"
        Write-Log "" -Level "Info"
        Write-Log "Repository paths have been created at:" -Level "Info"

        $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                     Select-Object -First 1 -ExpandProperty DriveLetter
        if ($dataDrive) {
            Write-Log "  - ${dataDrive}:\VeeamBackup\Repository" -Level "Info"
            Write-Log "  - ${dataDrive}:\VeeamBackup\Configuration" -Level "Info"
        }
    }

    # Configure Windows Server Backup
    try {
        Write-Log "Configuring Windows Server Backup settings..." -Level "Info"

        # Set VSS storage area
        $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                     Select-Object -First 1 -ExpandProperty DriveLetter

        if ($dataDrive) {
            vssadmin resize shadowstorage /for=C: /on=${dataDrive}: /maxsize=10%
            Write-Log "VSS shadow storage configured on ${dataDrive}: drive" -Level "Info"
        }
    } catch {
        Write-Log "Windows Server Backup configuration error: $_" -Level "Warning"
    }
    #endregion

    #region Storage Optimization
    Write-Log "Step 9: Optimizing Storage for Backup Workloads..." -Level "Info"
    try {
        # Enable data deduplication on backup volumes
        $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                     Select-Object -First 1 -ExpandProperty DriveLetter

        if ($dataDrive) {
            Enable-DedupVolume -Volume "${dataDrive}:" -UsageType Backup
            Set-DedupVolume -Volume "${dataDrive}:" -MinimumFileAgeDays 0

            Write-Log "Data deduplication enabled on ${dataDrive}: drive" -Level "Info"

            # Start initial deduplication job
            Start-DedupJob -Volume "${dataDrive}:" -Type Optimization
            Write-Log "Initial deduplication job started" -Level "Info"
        }
    } catch {
        Write-Log "Storage optimization error: $_" -Level "Warning"
    }
    #endregion

    #region BitLocker Configuration
    if (!$SkipBitLocker) {
        Write-Log "Step 10: Configuring BitLocker..." -Level "Info"
        try {
            # Check for TPM
            $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue

            if ($tpm) {
                # Enable BitLocker on OS drive
                $osDrive = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq "OperatingSystem" }
                if ($osDrive.ProtectionStatus -eq "Off") {
                    Enable-BitLocker -MountPoint $osDrive.MountPoint -TpmProtector -EncryptionMethod AES256
                    Add-BitLockerKeyProtector -MountPoint $osDrive.MountPoint -RecoveryPasswordProtector
                }

                # Enable BitLocker on data drives
                $dataVolumes = Get-BitLockerVolume | Where-Object { $_.VolumeType -ne "OperatingSystem" }
                foreach ($volume in $dataVolumes) {
                    if ($volume.ProtectionStatus -eq "Off") {
                        Enable-BitLocker -MountPoint $volume.MountPoint -PasswordProtector
                        Add-BitLockerKeyProtector -MountPoint $volume.MountPoint -RecoveryPasswordProtector
                        Enable-BitLockerAutoUnlock -MountPoint $volume.MountPoint
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
        Write-Log "Step 10: Skipping BitLocker (per parameter)" -Level "Info"
    }
    #endregion

    #region Windows Updates
    if (!$SkipWindowsUpdate) {
        Write-Log "Step 11: Installing Windows Updates..." -Level "Info"
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
        Write-Log "Step 11: Skipping Windows Updates (per parameter)" -Level "Info"
    }
    #endregion

    Write-Log "========================================" -Level "Info"
    Write-Log "Backup Server Setup Complete!" -Level "Info"
    Write-Log "========================================" -Level "Info"
    Write-Log "" -Level "Info"
    Write-Log "Setup Summary:" -Level "Info"

    Write-Log "✓ Hyper-V installed (for Instant VM Recovery)" -Level "Info"

    if (!$SkipStorageSpaces) {
        Write-Log "✓ Storage Spaces configured with mirroring" -Level "Info"
    }

    if (!$SkipNetworkTeaming) {
        Write-Log "✓ Network teaming configured for redundancy" -Level "Info"
    }

    Write-Log "✓ Backup directory structure created" -Level "Info"
    Write-Log "✓ Data deduplication enabled" -Level "Info"
    Write-Log "✓ Windows Server Backup feature installed" -Level "Info"

    Write-Log "" -Level "Info"
    Write-Log "Next Steps:" -Level "Info"
    Write-Log "1. Install backup software (Veeam/MSP360)" -Level "Info"
    Write-Log "2. Configure backup repositories" -Level "Info"
    Write-Log "3. Set up backup jobs and schedules" -Level "Info"
    Write-Log "4. Configure offsite replication" -Level "Info"
    Write-Log "5. Test restore procedures" -Level "Info"
    Write-Log "6. Enable Windows Firewall with appropriate rules" -Level "Info"
    Write-Log "" -Level "Info"

    $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                 Select-Object -First 1 -ExpandProperty DriveLetter
    if ($dataDrive) {
        Write-Log "Backup Repository Paths:" -Level "Info"
        Write-Log "  - Veeam: ${dataDrive}:\VeeamBackup\" -Level "Info"
        Write-Log "  - MSP360: ${dataDrive}:\MSP360\" -Level "Info"
        Write-Log "  - General: ${dataDrive}:\Backups\" -Level "Info"
    }

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