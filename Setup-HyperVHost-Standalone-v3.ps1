<#
.SYNOPSIS
    Complete Standalone Hyper-V Host Setup Script - MSP RMM Template Version
.DESCRIPTION
    Single-file setup script for Hyper-V host servers following MSP Script Library standards.
    Fully non-interactive when running from RMM ($RMM=1).

    IMPORTANT: This script typically requires 2-3 reboots:
    - Reboot 1: After computer rename (if needed)
    - Reboot 2: After Hyper-V and Windows Features installation
    - Reboot 3: After Windows Updates (optional)

    The script will log clearly when reboots are needed and can be re-run after each reboot.
.NOTES
    Author: DTC Inc
    Version: 3.1 MSP Template (Multi-Reboot Aware)
    Date: 2025-12-19
#>

## PLEASE COMMENT YOUR VARIABLES DIRECTLY BELOW HERE IF YOU'RE RUNNING FROM A RMM
## THIS IS HOW WE EASILY LET PEOPLE KNOW WHAT VARIABLES NEED SET IN THE RMM
## $RMM = 1                          # Set to 1 when running from RMM (REQUIRED)
## $ServerSequence = "01"            # Server sequence number 01-99 (REQUIRED)
## $SkipWindowsUpdate = $false       # Skip Windows Updates
## $SkipBitLocker = $false          # Skip BitLocker configuration
## $SkipNetworkTeaming = $false     # Skip network team configuration
## $TeamsOf = 2                     # NICs per SET team (2 or 4)
## $AutoNICTeaming = $false         # Auto-team by PCIe card
## $StorageRedundancy = "ers"       # Storage naming (ers/rrs/zrs/grs)
## $CompanyName = "DTC"             # Company name for branding
## $AcceptRAIDWarning = $false      # Accept single RAID disk warning

#Requires -RunAsAdministrator
#Requires -Version 5.1

# ============================================================================
# SECTION 1: RMM VARIABLE DECLARATION AND INPUT HANDLING
# ============================================================================

$ScriptVersion = "3.1"
$ScriptLogName = "HyperVHost-Setup-v3"
$ServerRole = "HV"  # Hyper-V Host role code

# Default configuration values
if ($null -eq $CompanyName) { $CompanyName = "DTC" }
if ($null -eq $SkipWindowsUpdate) { $SkipWindowsUpdate = $false }
if ($null -eq $SkipBitLocker) { $SkipBitLocker = $false }
if ($null -eq $SkipNetworkTeaming) { $SkipNetworkTeaming = $false }
if ($null -eq $TeamsOf) { $TeamsOf = 2 }
if ($null -eq $AutoNICTeaming) { $AutoNICTeaming = $false }
if ($null -eq $StorageRedundancy) { $StorageRedundancy = "ers" }
if ($null -eq $AcceptRAIDWarning) { $AcceptRAIDWarning = $false }

# Detect RMM mode
if ($RMM -ne 1) {
    # INTERACTIVE MODE - Get input from user
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Hyper-V Host Setup Script (v$ScriptVersion)" -ForegroundColor Cyan
    Write-Host "Interactive Mode" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "IMPORTANT: This script requires 2-3 reboots to complete" -ForegroundColor Yellow
    Write-Host "You can re-run the script after each reboot to continue" -ForegroundColor Yellow
    Write-Host ""

    # Server sequence (REQUIRED)
    $ValidInput = $false
    while (!$ValidInput) {
        Write-Host "Server Naming Configuration" -ForegroundColor Yellow
        Write-Host "Server will be named: ${ServerRole}XX (e.g., HV01, HV02)" -ForegroundColor Gray
        $sequence = Read-Host "Enter the sequence number for this server (1-99)"

        if ($sequence -match '^\d{1,2}$' -and [int]$sequence -ge 1 -and [int]$sequence -le 99) {
            $ServerSequence = "{0:d2}" -f [int]$sequence
            $ValidInput = $true
        } else {
            Write-Host "Invalid input. Please enter a number between 1 and 99." -ForegroundColor Red
        }
    }

    # Optional configurations
    $input = Read-Host "Enter company name (default: DTC)"
    if (![string]::IsNullOrEmpty($input)) { $CompanyName = $input }

    $response = Read-Host "Skip Windows Updates? (y/n, default: n)"
    if ($response -eq 'y') { $SkipWindowsUpdate = $true }

    $response = Read-Host "Skip BitLocker configuration? (y/n, default: n)"
    if ($response -eq 'y') { $SkipBitLocker = $true }

    $response = Read-Host "Skip network teaming? (y/n, default: n)"
    if ($response -eq 'y') { $SkipNetworkTeaming = $true }

    if (!$SkipNetworkTeaming) {
        $input = Read-Host "NICs per team - 2 or 4? (default: 2)"
        if ($input -eq "4") { $TeamsOf = 4 }

        $response = Read-Host "Auto-configure teams by PCIe card? (y/n, default: n)"
        if ($response -eq 'y') { $AutoNICTeaming = $true }
    }

    $input = Read-Host "Storage redundancy type (ers/rrs/zrs/grs, default: ers)"
    if ($input -in @("ers", "rrs", "zrs", "grs")) {
        $StorageRedundancy = $input
    }

    $Description = Read-Host "Enter a description for this setup (optional)"
    if ([string]::IsNullOrEmpty($Description)) {
        $Description = "Hyper-V Host setup for $CompanyName"
    }

    # Set log path for interactive mode
    $LogPath = "$ENV:WINDIR\logs"
} else {
    # RMM MODE - Use pre-set variables, no interaction allowed
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Hyper-V Host Setup Script (v$ScriptVersion)" -ForegroundColor Cyan
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

    $Description = "RMM-initiated Hyper-V Host setup for $CompanyName"

    # Set log path for RMM mode
    if ($null -ne $RMMScriptPath -and $RMMScriptPath -ne "") {
        $LogPath = "$RMMScriptPath\logs"
    } else {
        $LogPath = "$ENV:WINDIR\logs"
    }
}

# Build the new computer name
$NewComputerName = "${ServerRole}$ServerSequence"

# Ensure log directory exists
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$LogFile = Join-Path $LogPath "$ScriptLogName-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"

# ============================================================================
# SECTION 2: HELPER FUNCTIONS
# ============================================================================

# Track what needs reboots
$Global:RebootReasons = @()
$Global:RestartRequired = $false

function Add-RebootReason {
    param([string]$Reason)
    $Global:RebootReasons += $Reason
    $Global:RestartRequired = $true
}

# Storage helper functions
function Get-MediaType {
    param([Microsoft.Management.Infrastructure.CimInstance]$Disk)

    $physicalDisk = Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceId -eq $Disk.Number }
    if ($physicalDisk) {
        switch ($physicalDisk.MediaType) {
            "SSD" { return "ssd" }
            "HDD" { return "hdd" }
            "SCM" { return "nvme" }
            default { return "hdd" }
        }
    }

    if ($Disk.IsBoot) { return "ssd" }
    if ($Disk.Size -lt 1TB -and $Disk.Model -match "NVMe|BOSS|M\.2") { return "nvme" }
    return "hdd"
}

# Function for NIC details
function Get-NICDetails {
    $nicInfo = @()

    $adapters = Get-NetAdapter | Where-Object {
        $_.Virtual -eq $false -and
        $_.InterfaceDescription -notlike "*Virtual*" -and
        $_.InterfaceDescription -notlike "*Hyper-V*" -and
        $_.DriverFileName -notlike "usb*"
    }

    foreach ($adapter in $adapters) {
        $pnpDevice = Get-PnpDevice | Where-Object { $_.FriendlyName -eq $adapter.InterfaceDescription }

        $locationPath = $pnpDevice.LocationInfo
        $busNumber = "Unknown"
        $deviceNumber = "Unknown"
        $functionNumber = "Unknown"

        if ($locationPath -match "PCI bus (\d+), device (\d+), function (\d+)") {
            $busNumber = $matches[1]
            $deviceNumber = $matches[2]
            $functionNumber = $matches[3]
        }

        $nicDetail = [PSCustomObject]@{
            Name = $adapter.Name
            InterfaceDescription = $adapter.InterfaceDescription
            Status = $adapter.Status
            LinkSpeed = $adapter.LinkSpeed
            MacAddress = $adapter.MacAddress
            PCIBus = $busNumber
            PCIDevice = $deviceNumber
            PCIFunction = $functionNumber
            PCILocation = "Bus:$busNumber Dev:$deviceNumber Func:$functionNumber"
        }

        $nicInfo += $nicDetail
    }

    return $nicInfo | Sort-Object PCIBus, PCIDevice, PCIFunction
}

# ============================================================================
# SECTION 3: MAIN SCRIPT LOGIC
# ============================================================================

Start-Transcript -Path $LogFile

try {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Starting $ScriptLogName" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Description: $Description"
    Write-Host "Log Path: $LogFile"
    Write-Host "RMM Mode: $(if ($RMM -eq 1) { 'Yes' } else { 'No' })"
    Write-Host "Company Name: $CompanyName"
    Write-Host "Server Sequence: $ServerSequence"
    Write-Host "New Computer Name: $NewComputerName"
    Write-Host "Current Computer Name: $env:COMPUTERNAME"
    Write-Host ""
    Write-Host "Configuration Options:" -ForegroundColor Yellow
    Write-Host "  Skip Windows Update: $SkipWindowsUpdate"
    Write-Host "  Skip BitLocker: $SkipBitLocker"
    Write-Host "  Skip Network Teaming: $SkipNetworkTeaming"
    Write-Host "  NICs per Team: $TeamsOf"
    Write-Host "  Auto NIC Teaming: $AutoNICTeaming"
    Write-Host "  Storage Redundancy: $StorageRedundancy"
    Write-Host ""

    # ============================================================================
    # PHASE 1: INSTALL EVERYTHING THAT REQUIRES REBOOTS
    # ============================================================================

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "PHASE 1: Installing Components That Require Reboots" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    #region Step 1: Rename Computer (Requires Reboot)
    Write-Host "Step 1: Computer Naming Configuration..." -ForegroundColor Cyan

    if ($env:COMPUTERNAME -ne $NewComputerName) {
        Write-Host "Renaming computer from '$env:COMPUTERNAME' to '$NewComputerName'..."

        try {
            Rename-Computer -NewName $NewComputerName -Force -ErrorAction Stop
            Write-Host "Computer renamed successfully to '$NewComputerName'" -ForegroundColor Green
            Add-RebootReason "Computer rename to $NewComputerName"
        } catch {
            Write-Host "Failed to rename computer: $_" -ForegroundColor Red
            if ($RMM -ne 1) {
                $continue = Read-Host "Failed to rename computer. Continue anyway? (y/n)"
                if ($continue -ne 'y') {
                    throw "Setup cancelled due to computer rename failure"
                }
            }
        }
    } else {
        Write-Host "Computer name already set to '$NewComputerName'" -ForegroundColor Green
    }
    #endregion

    #region Step 2: Install ALL Windows Features and Roles (Many Require Reboots)
    Write-Host ""
    Write-Host "Step 2: Installing ALL Windows Features and Roles..." -ForegroundColor Cyan
    Write-Host "This includes Hyper-V and related components that require reboots" -ForegroundColor Yellow

    # Core Hyper-V installation
    $hyperV = Get-WindowsFeature -Name Hyper-V
    if ($hyperV.InstallState -ne "Installed") {
        Write-Host "Installing Hyper-V Role (REQUIRES REBOOT)..."
        $result = Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -IncludeAllSubFeature -Restart:$false
        if ($result.RestartNeeded -eq "Yes") {
            Add-RebootReason "Hyper-V Role Installation"
        }
        Write-Host "Hyper-V installed successfully" -ForegroundColor Green
    } else {
        Write-Host "Hyper-V already installed" -ForegroundColor Green
    }

    # Install ALL other features we need upfront
    Write-Host "Installing additional Windows features..."

    $featuresToInstall = @(
        @{Name = "SNMP-Service"; Description = "SNMP Service"},
        @{Name = "RSAT-Hyper-V-Tools"; Description = "Hyper-V Management Tools"},
        @{Name = "Hyper-V-PowerShell"; Description = "Hyper-V PowerShell Module"},
        @{Name = "Windows-Defender"; Description = "Windows Defender"},
        @{Name = "FS-Data-Deduplication"; Description = "Data Deduplication"},
        @{Name = "Multipath-IO"; Description = "MPIO for Storage"},
        @{Name = "Failover-Clustering"; Description = "Failover Clustering (for future use)"},
        @{Name = "RSAT-Clustering-PowerShell"; Description = "Clustering PowerShell"}
    )

    $featuresNeedingReboot = @()
    foreach ($feature in $featuresToInstall) {
        $feat = Get-WindowsFeature -Name $feature.Name -ErrorAction SilentlyContinue
        if ($feat -and $feat.InstallState -ne "Installed") {
            Write-Host "  Installing $($feature.Description)..."
            $result = Install-WindowsFeature -Name $feature.Name -IncludeManagementTools -Restart:$false
            if ($result.RestartNeeded -eq "Yes") {
                $featuresNeedingReboot += $feature.Description
            }
        } else {
            Write-Host "  $($feature.Description) already installed" -ForegroundColor Gray
        }
    }

    if ($featuresNeedingReboot.Count -gt 0) {
        Add-RebootReason "Windows Features: $($featuresNeedingReboot -join ', ')"
    }

    Write-Host "Windows features installation complete" -ForegroundColor Green
    #endregion

    #region Step 3: Install OEM Management Tools (May Require Reboot)
    Write-Host ""
    Write-Host "Step 3: Installing OEM Management Tools..." -ForegroundColor Cyan

    $Manufacturer = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer

    if ($Manufacturer -like "Dell*") {
        Write-Host "Dell hardware detected - installing Dell OpenManage and tools"

        # Check if already installed
        $omsaInstalled = Test-Path "C:\Program Files\Dell\SysMgt\oma\bin"

        if (!$omsaInstalled) {
            Write-Host "Dell OpenManage not found, installing..."

            # Download URLs for Dell tools
            $downloads = @(
                @{
                    Name = "OpenManage Server Administrator"
                    Url = "https://dl.dell.com/FOLDER11337880M/1/Windows_OMSA_11.0.1.0_A00.exe"
                    File = "$env:WINDIR\temp\OMSA_Setup.exe"
                    Args = "/s"
                },
                @{
                    Name = "iDRAC Service Module"
                    Url = "https://dl.dell.com/FOLDER11034445M/1/iDRAC-Service-Module-5.3.0.0_Windows_x64.exe"
                    File = "$env:WINDIR\temp\ISM_Setup.exe"
                    Args = "/s"
                },
                @{
                    Name = "Dell System Update"
                    Url = "https://dl.dell.com/FOLDER11689994M/1/Systems-Management_Application_NVD8W_WN64_2.0.2.3_A00.EXE"
                    File = "$env:WINDIR\temp\DSU_Setup.exe"
                    Args = "/s"
                },
                @{
                    Name = "Dell PERCCLI"
                    Url = "https://dl.dell.com/FOLDER09766599M/1/PERCCLI_7.2313.0_A16_Windows.zip"
                    File = "$env:WINDIR\temp\perccli.zip"
                    Args = $null
                }
            )

            foreach ($download in $downloads) {
                try {
                    Write-Host "  Downloading $($download.Name)..."
                    Invoke-WebRequest -Uri $download.Url -OutFile $download.File -UseBasicParsing

                    if ($download.File -like "*.zip") {
                        # Extract PERCCLI
                        Expand-Archive -Path $download.File -DestinationPath "$env:WINDIR\temp\perccli" -Force
                        $perccliExe = Get-ChildItem -Path "$env:WINDIR\temp\perccli" -Filter "perccli64.exe" -Recurse | Select-Object -First 1
                        if ($perccliExe) {
                            Copy-Item $perccliExe.FullName -Destination "C:\Program Files\Dell\perccli64.exe" -Force
                            Write-Host "  PERCCLI installed" -ForegroundColor Green
                        }
                    } else {
                        Write-Host "  Installing $($download.Name)..."
                        Start-Process -FilePath $download.File -ArgumentList $download.Args -Wait -NoNewWindow
                    }
                } catch {
                    Write-Host "  Failed to install $($download.Name): $_" -ForegroundColor Yellow
                }
            }

            # Dell tools may require reboot
            Add-RebootReason "Dell OpenManage and Tools Installation"
            Write-Host "Dell tools installed (MAY REQUIRE REBOOT)" -ForegroundColor Yellow
        } else {
            Write-Host "Dell OpenManage already installed" -ForegroundColor Green
        }

        # Try to find PERCCLI for RAID checking
        $perccliPaths = @(
            "C:\Program Files\Dell\perccli64.exe",
            "C:\Program Files\Dell\SysMgt\oma\bin\perccli64.exe",
            "$env:WINDIR\temp\perccli\perccli64.exe"
        )

        $perccliPath = $null
        foreach ($path in $perccliPaths) {
            if (Test-Path $path) {
                $perccliPath = $path
                break
            }
        }
    } else {
        Write-Host "Non-Dell hardware - skipping OEM tools"
    }
    #endregion

    #region Step 4: Windows Updates (Requires Reboot)
    if (!$SkipWindowsUpdate) {
        Write-Host ""
        Write-Host "Step 4: Installing Windows Updates..." -ForegroundColor Cyan
        Write-Host "This typically requires a reboot" -ForegroundColor Yellow

        try {
            # Ensure NuGet and PSWindowsUpdate are installed
            if (!(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -Force -Confirm:$false | Out-Null
            }

            if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
                Install-Module PSWindowsUpdate -Force -Confirm:$false | Out-Null
            }

            Import-Module PSWindowsUpdate

            Write-Host "Checking for updates..."
            $updates = Get-WindowsUpdate -NotCategory "Drivers"

            if ($updates) {
                Write-Host "Found $($updates.Count) updates to install..."
                Write-Host "Installing updates (this may take a while)..."

                # Install updates without auto-reboot
                Get-WindowsUpdate -NotCategory "Drivers" -AcceptAll -Install -IgnoreReboot | Out-Null

                Add-RebootReason "Windows Updates ($($updates.Count) updates installed)"
                Write-Host "Windows updates installed" -ForegroundColor Green
            } else {
                Write-Host "No updates available" -ForegroundColor Green
            }
        } catch {
            Write-Host "Windows Update error: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host ""
        Write-Host "Step 4: Skipping Windows Updates" -ForegroundColor Gray
    }
    #endregion

    # ============================================================================
    # CHECK IF REBOOT IS NEEDED BEFORE CONTINUING
    # ============================================================================

    if ($Global:RestartRequired) {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "REBOOT REQUIRED" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "The following changes require a reboot:" -ForegroundColor Yellow
        foreach ($reason in $Global:RebootReasons) {
            Write-Host "  - $reason" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "IMPORTANT: After reboot, re-run this script to continue configuration" -ForegroundColor Cyan
        Write-Host "The script will continue with Phase 2 (configuration) after reboot" -ForegroundColor Cyan
        Write-Host ""

        if ($RMM -eq 1) {
            Write-Host "RMM Mode: Automatic restart in 60 seconds..." -ForegroundColor Yellow
            Write-Host "The script should be scheduled to run again after reboot" -ForegroundColor Yellow
            shutdown /r /t 60 /c "Hyper-V Host Setup Phase 1 Complete - Restarting for Phase 2"
        } else {
            $response = Read-Host "Restart now? (y/n)"
            if ($response -eq 'y') {
                Write-Host "Restarting computer..."
                Write-Host "Remember to re-run this script after reboot!" -ForegroundColor Yellow
                Start-Sleep -Seconds 3
                Restart-Computer -Force
            } else {
                Write-Host "Please restart manually and re-run this script to continue" -ForegroundColor Yellow
            }
        }

        # Exit here if reboot is required
        exit 0
    }

    # ============================================================================
    # PHASE 2: CONFIGURATION (No Reboots Required)
    # ============================================================================

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "PHASE 2: Configuration (No Reboots Required)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    #region Step 5: Storage Configuration
    Write-Host "Step 5: Configuring Storage..." -ForegroundColor Cyan

    # Check RAID configuration if Dell with PERCCLI
    if ($perccliPath) {
        Write-Host "Checking RAID configuration with PERCCLI..."
        try {
            $raidInfo = & $perccliPath /c0 show
            # Log RAID info but don't block on it
            Write-Host "RAID configuration detected" -ForegroundColor Green
        } catch {
            Write-Host "Could not query RAID configuration" -ForegroundColor Yellow
        }
    }

    # Get all disks and analyze
    $allDisks = Get-Disk | Sort-Object Number
    Write-Host "Found $($allDisks.Count) disk(s)"

    # Check for RAID configuration issues
    $raidDisks = $allDisks | Where-Object { $_.Model -match "PERC|RAID|Virtual" }

    if ($raidDisks.Count -eq 1) {
        $raidDisk = $raidDisks[0]
        $partitions = Get-Partition -DiskNumber $raidDisk.Number -ErrorAction SilentlyContinue

        if ($partitions.Count -gt 2) {
            Write-Host "WARNING: Single RAID Virtual Disk Configuration Detected!" -ForegroundColor Yellow
            Write-Host "Current: OS and Data are on the same RAID virtual disk" -ForegroundColor Yellow
            Write-Host "Recommended: Separate RAID virtual disks for OS and Data" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "To fix this:" -ForegroundColor Cyan
            Write-Host "1. Boot into RAID controller (Ctrl+R or F2)" -ForegroundColor Cyan
            Write-Host "2. Delete current virtual disk" -ForegroundColor Cyan
            Write-Host "3. Create VD1: 2 disks, RAID1, ~500GB for OS" -ForegroundColor Cyan
            Write-Host "4. Create VD2: Remaining disks, RAID5/6/10 for Data" -ForegroundColor Cyan
            Write-Host ""

            if ($RMM -eq 1) {
                if (!$AcceptRAIDWarning) {
                    Write-Host "ERROR: Single RAID disk detected and AcceptRAIDWarning not set!" -ForegroundColor Red
                    Write-Host "Set `$AcceptRAIDWarning=`$true in RMM to continue with this configuration" -ForegroundColor Red
                    throw "RAID reconfiguration recommended. Set AcceptRAIDWarning=true to continue."
                }
                Write-Host "Continuing with single RAID disk (AcceptRAIDWarning=true)" -ForegroundColor Yellow
            } else {
                $response = Read-Host "Continue with suboptimal configuration? (y/n)"
                if ($response -ne 'y') {
                    throw "Please reconfigure RAID and re-run setup"
                }
            }
        }
    }

    # Configure storage
    $bootDisk = $allDisks | Where-Object { $_.IsBoot -eq $true } | Select-Object -First 1
    $dataDisks = $allDisks | Where-Object { $_.IsBoot -eq $false }

    if ($bootDisk) {
        Write-Host "Boot Disk: Disk $($bootDisk.Number) - $($bootDisk.Model)"

        # Check and expand OS partition
        try {
            $currentSize = (Get-Partition -DriveLetter C).Size
            $maxSize = (Get-PartitionSupportedSize -DriveLetter C).SizeMax

            if (($maxSize - $currentSize) -gt 1GB) {
                Write-Host "Expanding OS partition to maximum size..."
                Resize-Partition -DriveLetter C -Size $maxSize
                Write-Host "OS partition expanded successfully" -ForegroundColor Green
            } else {
                Write-Host "OS partition already at maximum size" -ForegroundColor Green
            }
        } catch {
            Write-Host "Could not resize OS partition: $_" -ForegroundColor Yellow
        }
    }

    # Configure data disks
    if ($dataDisks.Count -gt 0) {
        Write-Host "Configuring $($dataDisks.Count) data disk(s)..."

        $driveLetterIndex = 0
        $driveLetters = @('D', 'E', 'F', 'G', 'H')

        foreach ($disk in $dataDisks) {
            $diskNumber = $disk.Number
            $mediaType = Get-MediaType -Disk $disk
            $volumeLabel = "$StorageRedundancy-$mediaType-$('{0:d2}' -f ($driveLetterIndex + 1))"

            if ($disk.PartitionStyle -eq 'RAW') {
                Write-Host "Initializing Disk $diskNumber as GPT..."
                Initialize-Disk -Number $diskNumber -PartitionStyle GPT -PassThru | Out-Null

                $driveLetter = $driveLetters[$driveLetterIndex]
                $partition = New-Partition -DiskNumber $diskNumber -UseMaximumSize -DriveLetter $driveLetter
                Format-Volume -DriveLetter $partition.DriveLetter `
                             -FileSystem NTFS `
                             -AllocationUnitSize 65536 `
                             -NewFileSystemLabel $volumeLabel `
                             -Confirm:$false | Out-Null

                Write-Host "Configured Disk $diskNumber as $($partition.DriveLetter): drive ($volumeLabel)" -ForegroundColor Green
                $driveLetterIndex++
            } else {
                Write-Host "Disk $diskNumber already initialized"
            }
        }
    } else {
        Write-Host "No data disks found - storage will be on OS disk" -ForegroundColor Yellow
    }
    #endregion

    #region Step 6: Configure Hyper-V Settings
    Write-Host ""
    Write-Host "Step 6: Configuring Hyper-V Settings..." -ForegroundColor Cyan

    # Configure Hyper-V storage paths
    $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                 Select-Object -First 1 -ExpandProperty DriveLetter

    if ($dataDrive) {
        Write-Host "Configuring Hyper-V to use $dataDrive: drive for VM storage..."

        # Create directory structure
        $paths = @(
            "${dataDrive}:\Hyper-V\Virtual Hard Disks",
            "${dataDrive}:\Hyper-V\Virtual Machines",
            "${dataDrive}:\Hyper-V\Snapshots",
            "${dataDrive}:\Hyper-V\ISO"
        )

        foreach ($path in $paths) {
            if (!(Test-Path $path)) {
                New-Item -Path $path -ItemType Directory -Force | Out-Null
                Write-Host "  Created: $path"
            }
        }

        # Set Hyper-V host settings
        try {
            Set-VMHost -VirtualHardDiskPath "${dataDrive}:\Hyper-V\Virtual Hard Disks" -VirtualMachinePath "${dataDrive}:\Hyper-V"
            Write-Host "Hyper-V storage paths configured" -ForegroundColor Green
        } catch {
            Write-Host "Could not set Hyper-V paths (may need to restart Hyper-V service): $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "No data drive available - using default Hyper-V paths" -ForegroundColor Yellow
    }
    #endregion

    #region Step 7: Configure Network Teaming
    if (!$SkipNetworkTeaming) {
        Write-Host ""
        Write-Host "Step 7: Configuring Network Teaming..." -ForegroundColor Cyan

        # Clean up any existing virtual switches
        Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "SET*" } | Remove-VMSwitch -Force -ErrorAction SilentlyContinue

        # Get network adapters
        $adapters = Get-NetAdapter | Where-Object {
            $_.Status -eq 'Up' -and
            $_.Virtual -eq $false -and
            $_.InterfaceDescription -notlike "*Virtual*" -and
            $_.InterfaceDescription -notlike "*Hyper-V*"
        }

        if ($adapters.Count -ge 2) {
            Write-Host "Found $($adapters.Count) network adapters available for teaming"

            if ($AutoNICTeaming -or $RMM -eq 1) {
                # Auto-configure teams
                Write-Host "Auto-configuring network teams..."

                $nicDetails = Get-NICDetails
                $nicsByBus = $nicDetails | Where-Object { $_.Status -eq "Up" } | Group-Object PCIBus

                $teamNumber = 1
                foreach ($busGroup in $nicsByBus) {
                    if ($busGroup.Count -ge 2) {
                        $teamNics = $busGroup.Group | Select-Object -First $TeamsOf
                        $nicNames = $teamNics.Name

                        Write-Host "Creating SET$teamNumber with NICs: $($nicNames -join ', ')"

                        try {
                            New-VMSwitch -Name "SET$teamNumber" `
                                        -NetAdapterName $nicNames `
                                        -EnableEmbeddedTeaming $true `
                                        -AllowManagementOS $true

                            Rename-VMNetworkAdapter -Name "SET$teamNumber" -NewName "vNIC-Mgmt-SET$teamNumber" -ManagementOS

                            Write-Host "Created SET$teamNumber successfully" -ForegroundColor Green
                            $teamNumber++
                        } catch {
                            Write-Host "Failed to create SET$teamNumber: $_" -ForegroundColor Yellow
                        }
                    }
                }

                if ($teamNumber -eq 1) {
                    Write-Host "No teams created - may need manual configuration" -ForegroundColor Yellow
                }
            } else {
                # Manual mode
                Write-Host "Manual network team configuration selected"
                Write-Host "Available adapters:"
                $adapters | Format-Table Name, Status, LinkSpeed, InterfaceDescription

                $response = Read-Host "Create network team now? (y/n)"
                if ($response -eq 'y') {
                    Write-Host "Creating single SET team with all available adapters..."
                    try {
                        New-VMSwitch -Name "SET1" `
                                    -NetAdapterName $adapters.Name `
                                    -EnableEmbeddedTeaming $true `
                                    -AllowManagementOS $true

                        Rename-VMNetworkAdapter -Name "SET1" -NewName "vNIC-Mgmt-SET1" -ManagementOS
                        Write-Host "Created SET1 successfully" -ForegroundColor Green
                    } catch {
                        Write-Host "Failed to create team: $_" -ForegroundColor Yellow
                    }
                }
            }
        } else {
            Write-Host "Insufficient network adapters for teaming (need at least 2)" -ForegroundColor Yellow
        }
    } else {
        Write-Host ""
        Write-Host "Step 7: Skipping network teaming" -ForegroundColor Gray
    }
    #endregion

    #region Step 8: Configure Windows Settings
    Write-Host ""
    Write-Host "Step 8: Configuring Windows Settings..." -ForegroundColor Cyan

    # Disable Server Manager auto-start
    Get-ScheduledTask -TaskName ServerManager -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null

    # Set power plan to High Performance
    powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

    # Enable RDP
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

    # Disable Windows Firewall (temporarily for setup)
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

    # Set time zone (adjust as needed)
    # Set-TimeZone -Name "Eastern Standard Time"

    # Enable registry backup
    New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Configuration Manager\' `
                    -Name 'EnablePeriodicBackup' -PropertyType DWORD -Value 0x00000001 -Force -ErrorAction SilentlyContinue | Out-Null

    Write-Host "Windows settings configured" -ForegroundColor Green
    #endregion

    #region Step 9: Install Management Applications
    Write-Host ""
    Write-Host "Step 9: Installing Management Applications..." -ForegroundColor Cyan

    # Check for WinGet
    $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetPath) {
        $apps = @(
            @{id = "Mozilla.Firefox"; name = "Firefox"},
            @{id = "7zip.7zip"; name = "7-Zip"},
            @{id = "Notepad++.Notepad++"; name = "Notepad++"},
            @{id = "Microsoft.VisualStudioCode"; name = "Visual Studio Code"},
            @{id = "Microsoft.WindowsTerminal"; name = "Windows Terminal"}
        )

        foreach ($app in $apps) {
            Write-Host "Installing $($app.name)..."
            winget install --id $app.id --exact --silent --accept-package-agreements --accept-source-agreements
        }

        Write-Host "Applications installed" -ForegroundColor Green
    } else {
        Write-Host "WinGet not available - skipping application installation" -ForegroundColor Yellow
    }
    #endregion

    #region Step 10: Configure BitLocker (Optional)
    if (!$SkipBitLocker) {
        Write-Host ""
        Write-Host "Step 10: Configuring BitLocker..." -ForegroundColor Cyan

        $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
        if ($tpm) {
            # Enable BitLocker on OS drive
            $osDrive = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq "OperatingSystem" }
            if ($osDrive.ProtectionStatus -eq "Off") {
                Write-Host "Enabling BitLocker on OS drive..."
                Enable-BitLocker -MountPoint $osDrive.MountPoint -TpmProtector -EncryptionMethod AES256
                Add-BitLockerKeyProtector -MountPoint $osDrive.MountPoint -RecoveryPasswordProtector
                Write-Host "BitLocker enabled on OS drive" -ForegroundColor Green
            } else {
                Write-Host "BitLocker already enabled on OS drive" -ForegroundColor Green
            }

            # Enable on data drives
            $dataVolumes = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq "Data" }
            foreach ($volume in $dataVolumes) {
                if ($volume.ProtectionStatus -eq "Off") {
                    Write-Host "Enabling BitLocker on $($volume.MountPoint) drive..."
                    Enable-BitLocker -MountPoint $volume.MountPoint -PasswordProtector
                    Add-BitLockerKeyProtector -MountPoint $volume.MountPoint -RecoveryPasswordProtector
                    Enable-BitLockerAutoUnlock -MountPoint $volume.MountPoint
                    Write-Host "BitLocker enabled on $($volume.MountPoint)" -ForegroundColor Green
                }
            }
        } else {
            Write-Host "No TPM detected - skipping BitLocker" -ForegroundColor Yellow
        }
    } else {
        Write-Host ""
        Write-Host "Step 10: Skipping BitLocker configuration" -ForegroundColor Gray
    }
    #endregion

    # ============================================================================
    # SETUP COMPLETE
    # ============================================================================

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Hyper-V Host Setup Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Server Configuration:" -ForegroundColor Cyan
    Write-Host "  Name: $NewComputerName"
    Write-Host "  Company: $CompanyName"
    Write-Host "  Hyper-V: Installed and Configured"
    if (!$SkipNetworkTeaming) {
        Write-Host "  Network: SET Teams Configured"
    }
    Write-Host ""

    if ($dataDrive) {
        Write-Host "Storage Configuration:" -ForegroundColor Cyan
        Write-Host "  VM Storage: ${dataDrive}:\Hyper-V\"
        Write-Host "  ISO Storage: ${dataDrive}:\Hyper-V\ISO\"
    }
    Write-Host ""

    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Configure Windows Firewall rules"
    Write-Host "  2. Join to domain if required"
    Write-Host "  3. Install additional Hyper-V management tools"
    Write-Host "  4. Create virtual machines"
    Write-Host "  5. Configure backup solution"
    Write-Host "  6. Set up monitoring"
    Write-Host ""
    Write-Host "Log file: $LogFile"
    Write-Host ""

    # Final check for any pending reboots
    $pendingReboot = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    if ($pendingReboot) {
        Write-Host "NOTE: System has pending changes that may benefit from a reboot" -ForegroundColor Yellow

        if ($RMM -eq 1) {
            Write-Host "Consider scheduling a maintenance window for final reboot" -ForegroundColor Yellow
        } else {
            $response = Read-Host "Reboot now for optimal configuration? (y/n)"
            if ($response -eq 'y') {
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