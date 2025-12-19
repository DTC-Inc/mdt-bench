<#
.SYNOPSIS
    Complete Standalone Backup & Disaster Recovery Server Setup Script - MSP RMM Template Version
.DESCRIPTION
    Single-file setup script for BDR servers with Storage Spaces mirroring,
    optimized for Veeam Backup & Replication. Follows MSP Script Library template
    for RMM deployment. Fully non-interactive when $RMM=1.
.NOTES
    Author: DTC Inc
    Version: 3.0 MSP Template
    Date: 2025-12-19

    RMM Variables:
    - $RMM: Set to 1 for RMM mode (no prompts)
    - $ServerSequence: Server sequence number (01-99) REQUIRED
    - $CompanyName: Company name for branding (default: DTC)
    - $SkipWindowsUpdate: Skip Windows Updates (default: false)
    - $SkipBitLocker: Skip BitLocker configuration (default: false)
    - $SkipNetworkTeaming: Skip network team configuration (default: false)
    - $SkipStorageSpaces: Skip Storage Spaces configuration (default: false)
    - $InstallVeeam: Prepare for Veeam installation (default: false)
    - $StorageRedundancy: Storage naming (ers/rrs/zrs/grs, default: ers)
    - $AcceptSingleDisk: Accept single disk for storage (default: false)
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

## SECTION 1: RMM VARIABLE DECLARATION
## PLEASE COMMENT YOUR VARIABLES DIRECTLY BELOW HERE IF YOU'RE RUNNING FROM A RMM
## $RMM = 1
## $ServerSequence = "01"
## $CompanyName = "DTC"
## $SkipWindowsUpdate = $false
## $SkipBitLocker = $false
## $SkipNetworkTeaming = $false
## $SkipStorageSpaces = $false
## $InstallVeeam = $false
## $StorageRedundancy = "ers"
## $AcceptSingleDisk = $false

## SECTION 2: INPUT HANDLING
# Initialize variables with defaults if not set
if ($null -eq $CompanyName) { $CompanyName = "DTC" }
if ($null -eq $SkipWindowsUpdate) { $SkipWindowsUpdate = $false }
if ($null -eq $SkipBitLocker) { $SkipBitLocker = $false }
if ($null -eq $SkipNetworkTeaming) { $SkipNetworkTeaming = $false }
if ($null -eq $SkipStorageSpaces) { $SkipStorageSpaces = $false }
if ($null -eq $InstallVeeam) { $InstallVeeam = $false }
if ($null -eq $StorageRedundancy) { $StorageRedundancy = "ers" }
if ($null -eq $AcceptSingleDisk) { $AcceptSingleDisk = $false }

# Validate storage redundancy
if ($StorageRedundancy -notin @("ers", "rrs", "zrs", "grs")) {
    $StorageRedundancy = "ers"
}

# Server Role Code for Backup Server
$ServerRole = "BK"
$ScriptLogName = "BackupServer-Setup-v3"

# Detect RMM mode
if ($RMM -ne 1) {
    # Interactive mode - prompt for required inputs
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Backup Server Setup Script (v3)" -ForegroundColor Cyan
    Write-Host "Interactive Mode" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Get server sequence
    $ValidInput = $false
    while (!$ValidInput) {
        $sequence = Read-Host "Enter the sequence number for this Backup Server (1-99)"
        if ($sequence -match '^\d{1,2}$' -and [int]$sequence -ge 1 -and [int]$sequence -le 99) {
            $ServerSequence = "{0:d2}" -f [int]$sequence
            $ValidInput = $true
        } else {
            Write-Host "Invalid input. Please enter a number between 1 and 99." -ForegroundColor Yellow
        }
    }

    # Get company name
    $input = Read-Host "Enter company name (default: DTC)"
    if (![string]::IsNullOrEmpty($input)) { $CompanyName = $input }

    # Get storage redundancy type
    Write-Host "Storage redundancy types:"
    Write-Host "  ers - Economically Redundant Storage"
    Write-Host "  rrs - Regionally Redundant Storage"
    Write-Host "  zrs - Zone Redundant Storage"
    Write-Host "  grs - Geographically Redundant Storage"
    $input = Read-Host "Enter storage redundancy type (default: ers)"
    if ($input -in @("ers", "rrs", "zrs", "grs")) { $StorageRedundancy = $input }

    # Ask about Veeam
    $response = Read-Host "Prepare directories for Veeam installation? (y/n, default: n)"
    if ($response -eq 'y') { $InstallVeeam = $true }

    # Ask about Storage Spaces
    $response = Read-Host "Skip Storage Spaces configuration? (y/n, default: n)"
    if ($response -eq 'y') { $SkipStorageSpaces = $true }

    # Ask about updates
    $response = Read-Host "Skip Windows Updates? (y/n, default: n)"
    if ($response -eq 'y') { $SkipWindowsUpdate = $true }

    # Ask about network teaming
    $response = Read-Host "Skip network teaming configuration? (y/n, default: n)"
    if ($response -eq 'y') { $SkipNetworkTeaming = $true }

    # Ask about BitLocker
    $response = Read-Host "Skip BitLocker configuration? (y/n, default: n)"
    if ($response -eq 'y') { $SkipBitLocker = $true }

    $Description = Read-Host "Enter a description for this setup (optional)"
    if ([string]::IsNullOrEmpty($Description)) {
        $Description = "Backup Server setup for $CompanyName"
    }

    # Set log path for interactive mode
    $LogPath = "$ENV:WINDIR\logs"
} else {
    # RMM mode - use variables passed from RMM
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Backup Server Setup Script (v3)" -ForegroundColor Cyan
    Write-Host "RMM Mode - Non-Interactive" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan

    # Validate required variables
    if ($null -eq $ServerSequence) {
        Write-Host "ERROR: ServerSequence is required when running from RMM!" -ForegroundColor Red
        Write-Host "Set `$ServerSequence to a value between 01 and 99" -ForegroundColor Red
        exit 1
    }

    # Format server sequence
    if ($ServerSequence -match '^\d{1,2}$' -and [int]$ServerSequence -ge 1 -and [int]$ServerSequence -le 99) {
        $ServerSequence = "{0:d2}" -f [int]$ServerSequence
    } else {
        Write-Host "ERROR: Invalid ServerSequence value: $ServerSequence" -ForegroundColor Red
        Write-Host "Must be a number between 1 and 99" -ForegroundColor Red
        exit 1
    }

    $Description = "RMM-initiated Backup Server setup for $CompanyName"

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

## SECTION 3: MAIN SCRIPT LOGIC
Start-Transcript -Path $LogFile

Write-Host "========================================" -ForegroundColor Green
Write-Host "Starting $ScriptLogName" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Description: $Description"
Write-Host "Log Path: $LogFile"
Write-Host "RMM Mode: $(if ($RMM -eq 1) { 'Yes' } else { 'No' })"
Write-Host "Company Name: $CompanyName"
Write-Host "Server Sequence: $ServerSequence"
Write-Host ""
Write-Host "Configuration Options:" -ForegroundColor Yellow
Write-Host "  Storage Redundancy: $StorageRedundancy"
Write-Host "  Prepare for Veeam: $InstallVeeam"
Write-Host "  Skip Storage Spaces: $SkipStorageSpaces"
Write-Host "  Skip Windows Update: $SkipWindowsUpdate"
Write-Host "  Skip Network Teaming: $SkipNetworkTeaming"
Write-Host "  Skip BitLocker: $SkipBitLocker"
Write-Host ""

# Error handling
$ErrorActionPreference = "Stop"
$RestartRequired = $false

try {
    #region Step 0: Server Naming
    Write-Host "Step 0: Configuring Server Name..." -ForegroundColor Cyan
    try {
        $currentName = $env:COMPUTERNAME
        $NewComputerName = "${ServerRole}$ServerSequence"

        if ($currentName -ne $NewComputerName) {
            Write-Host "Renaming computer from $currentName to $NewComputerName"
            Rename-Computer -NewName $NewComputerName -Force
            Write-Host "Computer renamed to $NewComputerName. Restart required." -ForegroundColor Green
            $RestartRequired = $true
        } else {
            Write-Host "Computer name already set to $NewComputerName" -ForegroundColor Green
        }
    } catch {
        Write-Host "Server naming error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Storage Spaces Configuration
    if (!$SkipStorageSpaces) {
        Write-Host ""
        Write-Host "Step 1: Configuring Storage Spaces with Mirroring..." -ForegroundColor Cyan
        try {
            # Clean up any existing storage pools
            Write-Host "Cleaning up existing storage configurations..."
            Get-VirtualDisk -ErrorAction SilentlyContinue | Remove-VirtualDisk -Confirm:$false -ErrorAction SilentlyContinue
            Get-StoragePool -ErrorAction SilentlyContinue | Where-Object { $_.IsPrimordial -eq $false } |
                Remove-StoragePool -Confirm:$false -ErrorAction SilentlyContinue

            # Reset physical disks
            Get-PhysicalDisk | Reset-PhysicalDisk -ErrorAction SilentlyContinue

            # Get available disks for pool
            $availableDisks = Get-PhysicalDisk -CanPool $true

            if ($availableDisks.Count -ge 2) {
                Write-Host "Found $($availableDisks.Count) disks available for Storage Spaces"
                $availableDisks | Format-Table FriendlyName, @{L='Size(GB)';E={[math]::Round($_.Size/1GB,2)}}, MediaType -AutoSize

                if ($RMM -eq 1) {
                    # Auto-create in RMM mode
                    Write-Host "Creating mirrored storage pool automatically..."
                    $createPool = $true
                } else {
                    $response = Read-Host "Create mirrored storage pool with these disks? (y/n)"
                    $createPool = ($response -eq 'y')
                }

                if ($createPool) {
                    $storageSubsystem = Get-StorageSubsystem | Select-Object -First 1 -ExpandProperty FriendlyName

                    # Create storage pool
                    Write-Host "Creating storage pool 'BackupPool'..."
                    New-StoragePool -FriendlyName "BackupPool" `
                                   -StorageSubsystemFriendlyName $storageSubsystem `
                                   -PhysicalDisks $availableDisks

                    # Create mirrored virtual disk
                    $volumeLabel = "$StorageRedundancy-mirror-01"
                    Write-Host "Creating mirrored virtual disk '$volumeLabel'..."

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

                    Write-Host "Storage Spaces configured with mirroring" -ForegroundColor Green
                }
            } else {
                Write-Host "Insufficient disks for Storage Spaces mirroring (need at least 2)" -ForegroundColor Yellow

                if ($RMM -eq 1 -and !$AcceptSingleDisk) {
                    Write-Host "ERROR: Single disk configuration detected!" -ForegroundColor Red
                    Write-Host "Set `$AcceptSingleDisk=`$true in RMM to continue with this configuration" -ForegroundColor Red
                    exit 1
                }

                if ($RMM -ne 1) {
                    $response = Read-Host "Continue with single disk configuration? (y/n)"
                    if ($response -ne 'y') {
                        Write-Host "Storage configuration cancelled" -ForegroundColor Yellow
                        exit 1
                    }
                }

                # Fallback to standard disk configuration
                Write-Host "Configuring standard disk storage..."
                $dataDisks = Get-Disk | Where-Object { $_.IsBoot -eq $false -and $_.IsSystem -eq $false }

                if ($dataDisks) {
                    $disk = $dataDisks | Select-Object -First 1
                    if ($disk.PartitionStyle -eq 'RAW') {
                        Initialize-Disk -Number $disk.Number -PartitionStyle GPT
                    }

                    # Check if partition already exists
                    $existingPartition = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue |
                                        Where-Object { $_.Type -eq 'Basic' }

                    if (!$existingPartition) {
                        New-Partition -DiskNumber $disk.Number -UseMaximumSize -DriveLetter D
                        Format-Volume -DriveLetter D -FileSystem NTFS `
                                     -AllocationUnitSize 65536 `
                                     -NewFileSystemLabel "$StorageRedundancy-backup-01" `
                                     -Confirm:$false
                        Write-Host "Data disk configured as D: drive" -ForegroundColor Green
                    }
                }
            }
        } catch {
            Write-Host "Storage Spaces configuration error: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host ""
        Write-Host "Step 1: Skipping Storage Spaces configuration" -ForegroundColor Gray
    }
    #endregion

    #region Filesystem Configuration for Backup Software
    Write-Host ""
    Write-Host "Step 2: Creating Backup Software Directory Structure..." -ForegroundColor Cyan
    try {
        # Find data drive
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

            Write-Host "Backup directory structure created on $dataPath drive" -ForegroundColor Green
        } else {
            Write-Host "No data drive found for backup directories" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Filesystem configuration error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Network Configuration
    Write-Host ""
    Write-Host "Step 3: Configuring Network with Redundancy..." -ForegroundColor Cyan
    if (!$SkipNetworkTeaming) {
        try {
            # Clean up existing teams
            Get-NetLbfoTeam -ErrorAction SilentlyContinue | Remove-NetLbfoTeam -Confirm:$false -ErrorAction SilentlyContinue
            Get-NetSwitchTeam -ErrorAction SilentlyContinue | Remove-NetSwitchTeam -Confirm:$false -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5

            # Get available network adapters
            $adapters = Get-NetAdapter | Where-Object {
                $_.Status -eq 'Up' -and
                $_.Virtual -eq $false -and
                $_.InterfaceDescription -notlike "*Virtual*" -and
                $_.InterfaceDescription -notlike "*Hyper-V*"
            }

            if ($adapters.Count -ge 2) {
                Write-Host "Found $($adapters.Count) network adapters available for teaming"

                if ($RMM -eq 1) {
                    # Auto-create team in RMM mode
                    Write-Host "Creating network team automatically..."
                    $createTeam = $true
                } else {
                    $adapters | Format-Table Name, InterfaceDescription, LinkSpeed, Status -AutoSize
                    $response = Read-Host "Create network team for redundancy? (y/n)"
                    $createTeam = ($response -eq 'y')
                }

                if ($createTeam) {
                    # Check if Hyper-V is installed (will be after step 5)
                    $hyperVInstalled = (Get-WindowsFeature -Name Hyper-V -ErrorAction SilentlyContinue).InstallState -eq "Installed"

                    if ($hyperVInstalled) {
                        # Create SET team for Hyper-V
                        Write-Host "Creating Switch Embedded Team (SET)..."
                        New-VMSwitch -Name "BackupSET" `
                                    -NetAdapterName $adapters.Name `
                                    -EnableEmbeddedTeaming $true `
                                    -AllowManagementOS $true

                        Rename-VMNetworkAdapter -Name "BackupSET" -NewName "vNIC-Backup" -ManagementOS
                        Write-Host "SET team created successfully" -ForegroundColor Green
                    } else {
                        # Create LBFO team
                        Write-Host "Creating LBFO network team..."
                        New-NetLbfoTeam -Name "BackupTeam" `
                                       -TeamMembers $adapters.Name `
                                       -LoadBalancingAlgorithm Dynamic `
                                       -TeamingMode SwitchIndependent `
                                       -Confirm:$false
                        Write-Host "LBFO team created successfully" -ForegroundColor Green
                    }
                }
            } else {
                Write-Host "Insufficient network adapters for teaming (found: $($adapters.Count))"
            }
        } catch {
            Write-Host "Network configuration error: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host ""
        Write-Host "Step 3: Skipping network teaming" -ForegroundColor Gray
    }
    #endregion

    #region Windows Configuration
    Write-Host ""
    Write-Host "Step 4: Configuring Windows Settings..." -ForegroundColor Cyan
    try {
        # Disable Windows Firewall temporarily
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

        # Disable Server Manager auto-start
        Get-ScheduledTask -TaskName ServerManager -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null

        # Enable registry backup
        New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Configuration Manager\' `
                        -Name 'EnablePeriodicBackup' -PropertyType DWORD -Value 0x00000001 -Force -ErrorAction SilentlyContinue | Out-Null

        # Set power plan to High Performance
        powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

        # Disable hibernation
        powercfg -h off

        Write-Host "Windows configuration completed" -ForegroundColor Green
    } catch {
        Write-Host "Windows configuration error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Deploy Windows Features & Hyper-V
    Write-Host ""
    Write-Host "Step 5: Installing Windows Features & Hyper-V..." -ForegroundColor Cyan
    try {
        # Install Hyper-V for Instant VM Recovery
        Write-Host "Installing Hyper-V (required for Instant VM Recovery)..."
        $hyperV = Get-WindowsFeature -Name Hyper-V
        if ($hyperV.InstallState -ne "Installed") {
            Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -IncludeAllSubFeature -Restart:$false | Out-Null
            Write-Host "Hyper-V installed successfully" -ForegroundColor Green
            $RestartRequired = $true

            # Configure Hyper-V paths if data drive exists
            $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                         Select-Object -First 1 -ExpandProperty DriveLetter
            if ($dataDrive) {
                # Create Hyper-V directories
                New-Item -Path "${dataDrive}:\Hyper-V\Virtual Hard Disks" -ItemType Directory -Force | Out-Null
                New-Item -Path "${dataDrive}:\Hyper-V\Virtual Machines" -ItemType Directory -Force | Out-Null
                New-Item -Path "${dataDrive}:\Hyper-V\Instant Recovery" -ItemType Directory -Force | Out-Null

                # Set paths (will apply after restart)
                Set-VMHost -VirtualHardDiskPath "${dataDrive}:\Hyper-V\Virtual Hard Disks"
                Set-VMHost -VirtualMachinePath "${dataDrive}:\Hyper-V"

                Write-Host "Hyper-V configured with paths on ${dataDrive}: drive" -ForegroundColor Green
            }
        } else {
            Write-Host "Hyper-V already installed"
        }

        # Install deduplication for backup storage efficiency
        Write-Host "Installing Data Deduplication feature..."
        Enable-WindowsOptionalFeature -Online -FeatureName Dedup-Core -All -NoRestart | Out-Null

        # Install .NET Framework
        Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -NoRestart | Out-Null
        Enable-WindowsOptionalFeature -Online -FeatureName NetFx4-AdvSrvs -All -NoRestart | Out-Null

        # Install Windows Server Backup feature
        Install-WindowsFeature -Name Windows-Server-Backup -IncludeManagementTools | Out-Null

        Write-Host "Windows features and Hyper-V installed successfully" -ForegroundColor Green
    } catch {
        Write-Host "Feature installation error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Deploy OEM Tools
    Write-Host ""
    Write-Host "Step 6: Installing OEM Tools..." -ForegroundColor Cyan
    try {
        $Manufacturer = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer

        if ($Manufacturer -like "Dell*") {
            Write-Host "Dell hardware detected - installing OpenManage"

            # Download URLs for Dell tools
            $omsaUrl = "https://dl.dell.com/FOLDER11337880M/1/Windows_OMSA_11.0.1.0_A00.exe"
            $ismUrl = "https://dl.dell.com/FOLDER11034445M/1/iDRAC-Service-Module-5.3.0.0_Windows_x64.exe"

            # Download and install OMSA
            Write-Host "Downloading OpenManage Server Administrator..."
            Invoke-WebRequest -Uri $omsaUrl -OutFile "$env:WINDIR\temp\OMSA_Setup.exe" -UseBasicParsing
            Write-Host "Installing OpenManage Server Administrator..."
            Start-Process -FilePath "$env:WINDIR\temp\OMSA_Setup.exe" -ArgumentList "/s" -Wait -NoNewWindow

            # Download and install ISM
            Write-Host "Downloading iDRAC Service Module..."
            Invoke-WebRequest -Uri $ismUrl -OutFile "$env:WINDIR\temp\ISM_Setup.exe" -UseBasicParsing
            Write-Host "Installing iDRAC Service Module..."
            Start-Process -FilePath "$env:WINDIR\temp\ISM_Setup.exe" -ArgumentList "/s" -Wait -NoNewWindow

            Write-Host "Dell tools installation completed" -ForegroundColor Green
        } else {
            Write-Host "Non-Dell hardware - skipping OEM tools"
        }
    } catch {
        Write-Host "OEM tools installation error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Deploy Applications
    Write-Host ""
    Write-Host "Step 7: Installing Applications..." -ForegroundColor Cyan
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
                @{id = "Notepad++.Notepad++"; name = "Notepad++"},
                @{id = "Microsoft.PowerShell"; name = "PowerShell 7"}
            )

            foreach ($app in $apps) {
                Write-Host "Installing $($app.name)..."
                winget install --id $app.id --exact --silent --accept-package-agreements --accept-source-agreements
            }

            Write-Host "Applications installed" -ForegroundColor Green
        } else {
            Write-Host "WinGet not available - skipping application installation" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Application installation error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Backup Software Configuration
    Write-Host ""
    Write-Host "Step 8: Backup Software Configuration..." -ForegroundColor Cyan

    if ($InstallVeeam) {
        Write-Host "Veeam installation preparation:" -ForegroundColor Yellow
        Write-Host "  - Repository directories have been created"
        Write-Host "  - Please download Veeam Backup & Replication from:"
        Write-Host "    https://www.veeam.com/downloads.html"

        $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                     Select-Object -First 1 -ExpandProperty DriveLetter
        if ($dataDrive) {
            Write-Host ""
            Write-Host "Repository paths configured at:" -ForegroundColor Cyan
            Write-Host "  - ${dataDrive}:\VeeamBackup\Repository"
            Write-Host "  - ${dataDrive}:\VeeamBackup\Configuration"
        }
    }

    # Configure Windows Server Backup
    try {
        Write-Host "Configuring Windows Server Backup settings..."

        # Set VSS storage area
        $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                     Select-Object -First 1 -ExpandProperty DriveLetter

        if ($dataDrive) {
            vssadmin resize shadowstorage /for=C: /on=${dataDrive}: /maxsize=10% 2>&1 | Out-Null
            Write-Host "VSS shadow storage configured on ${dataDrive}: drive" -ForegroundColor Green
        }
    } catch {
        Write-Host "Windows Server Backup configuration error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Storage Optimization
    Write-Host ""
    Write-Host "Step 9: Optimizing Storage for Backup Workloads..." -ForegroundColor Cyan
    try {
        # Enable data deduplication on backup volumes
        $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                     Select-Object -First 1 -ExpandProperty DriveLetter

        if ($dataDrive) {
            Enable-DedupVolume -Volume "${dataDrive}:" -UsageType Backup
            Set-DedupVolume -Volume "${dataDrive}:" -MinimumFileAgeDays 0

            Write-Host "Data deduplication enabled on ${dataDrive}: drive" -ForegroundColor Green

            # Start initial deduplication job
            Start-DedupJob -Volume "${dataDrive}:" -Type Optimization
            Write-Host "Initial deduplication job started" -ForegroundColor Green
        }
    } catch {
        Write-Host "Storage optimization error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region BitLocker Configuration
    if (!$SkipBitLocker) {
        Write-Host ""
        Write-Host "Step 10: Configuring BitLocker..." -ForegroundColor Cyan
        try {
            # Check for TPM
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
                $dataVolumes = Get-BitLockerVolume | Where-Object { $_.VolumeType -ne "OperatingSystem" }
                foreach ($volume in $dataVolumes) {
                    if ($volume.ProtectionStatus -eq "Off") {
                        Enable-BitLocker -MountPoint $volume.MountPoint -PasswordProtector
                        Add-BitLockerKeyProtector -MountPoint $volume.MountPoint -RecoveryPasswordProtector
                        Enable-BitLockerAutoUnlock -MountPoint $volume.MountPoint
                        Write-Host "BitLocker enabled on $($volume.MountPoint) drive" -ForegroundColor Green
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
        Write-Host "Step 10: Skipping BitLocker" -ForegroundColor Gray
    }
    #endregion

    #region Windows Updates
    if (!$SkipWindowsUpdate) {
        Write-Host ""
        Write-Host "Step 11: Installing Windows Updates..." -ForegroundColor Cyan
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
        Write-Host "Step 11: Skipping Windows Updates" -ForegroundColor Gray
    }
    #endregion

    # Setup Complete
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Backup Server Setup Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Server Configuration:" -ForegroundColor Cyan
    Write-Host "  Name: $NewComputerName"
    Write-Host "  Company: $CompanyName"
    Write-Host "  Storage Redundancy: $StorageRedundancy"
    Write-Host ""

    Write-Host "Installed Components:" -ForegroundColor Cyan
    Write-Host "  ✓ Hyper-V (for Instant VM Recovery)" -ForegroundColor Green
    if (!$SkipStorageSpaces) {
        Write-Host "  ✓ Storage Spaces with mirroring" -ForegroundColor Green
    }
    if (!$SkipNetworkTeaming) {
        Write-Host "  ✓ Network teaming for redundancy" -ForegroundColor Green
    }
    Write-Host "  ✓ Backup directory structure" -ForegroundColor Green
    Write-Host "  ✓ Data deduplication" -ForegroundColor Green
    Write-Host "  ✓ Windows Server Backup feature" -ForegroundColor Green
    Write-Host ""

    $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                 Select-Object -First 1 -ExpandProperty DriveLetter
    if ($dataDrive) {
        Write-Host "Backup Repository Paths:" -ForegroundColor Cyan
        Write-Host "  - Veeam: ${dataDrive}:\VeeamBackup\"
        Write-Host "  - MSP360: ${dataDrive}:\MSP360\"
        Write-Host "  - General: ${dataDrive}:\Backups\"
        Write-Host "  - Hyper-V: ${dataDrive}:\Hyper-V\"
        Write-Host ""
    }

    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Restart server to apply all changes"
    Write-Host "  2. Install backup software (Veeam/MSP360)"
    Write-Host "  3. Configure backup repositories"
    Write-Host "  4. Set up backup jobs and schedules"
    Write-Host "  5. Configure offsite replication"
    Write-Host "  6. Test restore procedures"
    Write-Host "  7. Enable Windows Firewall with appropriate rules"
    Write-Host ""
    Write-Host "Log file: $LogFile"

    # Handle restart
    if ($RestartRequired) {
        Write-Host ""
        Write-Host "RESTART REQUIRED" -ForegroundColor Yellow

        if ($RMM -eq 1) {
            Write-Host "RMM Mode: Automatic restart in 60 seconds..." -ForegroundColor Yellow
            Write-Host "Run 'shutdown /a' to cancel" -ForegroundColor Yellow
            shutdown /r /t 60 /c "Backup Server setup complete. Restarting in 60 seconds..."
        } else {
            $response = Read-Host "Restart now? (y/n)"
            if ($response -eq 'y') {
                Write-Host "Restarting computer..."
                Restart-Computer -Force
            } else {
                Write-Host "Please restart manually to apply all changes" -ForegroundColor Yellow
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