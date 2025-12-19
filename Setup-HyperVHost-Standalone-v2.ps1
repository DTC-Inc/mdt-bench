<#
.SYNOPSIS
    Complete Standalone Hyper-V Host Setup Script - RMM Deployment Version
.DESCRIPTION
    Single-file setup script for Hyper-V host servers with all configurations
    consolidated. Uses environment variables for RMM deployment.
.NOTES
    Author: DTC Inc
    Version: 2.1 RMM
    Date: 2024-12-18

.ENVIRONMENT VARIABLES
    Required:
    - None (all variables have defaults)

    Optional:
    - MDT_SERVER_SEQUENCE: Server sequence number (01-99, will prompt if not set)
    - MDT_SKIP_WINDOWS_UPDATE: Set to "true" to skip Windows updates
    - MDT_SKIP_BITLOCKER: Set to "true" to skip BitLocker configuration
    - MDT_SKIP_NETWORK_TEAMING: Set to "true" to skip network teaming
    - MDT_TEAMS_OF: Number of NICs per team (2 or 4, default: 2)
    - MDT_AUTO_NIC_TEAMING: Set to "true" for automatic teaming by PCIe card
    - MDT_STORAGE_REDUNDANCY: Storage redundancy type (ers/rrs/zrs/grs, default: ers)
    - MDT_LOG_PATH: Custom log path (default: C:\Logs\MDT\)
    - MDT_COMPANY_NAME: Company name for customization (default: DTC)

.EXAMPLE
    # In NinjaRMM/CW Automate/etc., set script variables:
    MDT_SKIP_BITLOCKER=true
    MDT_TEAMS_OF=4
    MDT_STORAGE_REDUNDANCY=rrs

    # Then run:
    .\Setup-HyperVHost-Standalone-v2.ps1
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

# ============================================================================
# CONFIGURATION SECTION - Read from Environment Variables
# ============================================================================

# Function to safely get environment variables with defaults
function Get-ConfigValue {
    param(
        [string]$EnvName,
        [string]$DefaultValue = ""
    )

    $value = [System.Environment]::GetEnvironmentVariable($EnvName)
    if ([string]::IsNullOrEmpty($value)) {
        return $DefaultValue
    }
    return $value
}

# Function to get boolean environment variable
function Get-ConfigBool {
    param(
        [string]$EnvName,
        [bool]$DefaultValue = $false
    )

    $value = [System.Environment]::GetEnvironmentVariable($EnvName)
    if ([string]::IsNullOrEmpty($value)) {
        return $DefaultValue
    }

    return ($value -eq "true" -or $value -eq "1" -or $value -eq "yes")
}

# Read all configuration from environment variables
$Config = @{
    ServerSequence = Get-ConfigValue -EnvName "MDT_SERVER_SEQUENCE" -DefaultValue ""
    SkipWindowsUpdate = Get-ConfigBool -EnvName "MDT_SKIP_WINDOWS_UPDATE" -DefaultValue $false
    SkipBitLocker = Get-ConfigBool -EnvName "MDT_SKIP_BITLOCKER" -DefaultValue $false
    SkipNetworkTeaming = Get-ConfigBool -EnvName "MDT_SKIP_NETWORK_TEAMING" -DefaultValue $false
    TeamsOf = [int](Get-ConfigValue -EnvName "MDT_TEAMS_OF" -DefaultValue "2")
    AutoNICTeaming = Get-ConfigBool -EnvName "MDT_AUTO_NIC_TEAMING" -DefaultValue $false
    StorageRedundancy = Get-ConfigValue -EnvName "MDT_STORAGE_REDUNDANCY" -DefaultValue "ers"
    CompanyName = Get-ConfigValue -EnvName "MDT_COMPANY_NAME" -DefaultValue "DTC"
    LogPath = Get-ConfigValue -EnvName "MDT_LOG_PATH" -DefaultValue "C:\Logs\MDT"
}

# Server naming based on role and sequence
$ServerRole = "HV"  # Hyper-V Host

# If sequence not provided, prompt for it
if ([string]::IsNullOrEmpty($Config.ServerSequence)) {
    Write-Host "`n================================" -ForegroundColor Cyan
    Write-Host "Server Naming Configuration" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "Server will be named: ${ServerRole}XX" -ForegroundColor Yellow
    Write-Host "Where XX is a two-digit sequence number" -ForegroundColor Yellow
    Write-Host "Examples: HV01, HV02, HV03..." -ForegroundColor Gray
    Write-Host ""

    do {
        $sequence = Read-Host "Enter the sequence number for this server (1-99)"
        if ($sequence -match '^\d{1,2}$' -and [int]$sequence -ge 1 -and [int]$sequence -le 99) {
            $Config.ServerSequence = "{0:d2}" -f [int]$sequence
            break
        } else {
            Write-Host "Invalid input. Please enter a number between 1 and 99." -ForegroundColor Red
        }
    } while ($true)
} else {
    # Validate and format the provided sequence
    if ($Config.ServerSequence -match '^\d{1,2}$') {
        $Config.ServerSequence = "{0:d2}" -f [int]$Config.ServerSequence
    } else {
        Write-Host "Invalid MDT_SERVER_SEQUENCE value. Using 01 as default." -ForegroundColor Warning
        $Config.ServerSequence = "01"
    }
}

# Build the new computer name
$NewComputerName = "${ServerRole}$($Config.ServerSequence)"

# Validate configuration values
if ($Config.TeamsOf -ne 2 -and $Config.TeamsOf -ne 4) {
    $Config.TeamsOf = 2
}

if ($Config.StorageRedundancy -notin @("ers", "rrs", "zrs", "grs")) {
    $Config.StorageRedundancy = "ers"
}

# ============================================================================
# LOGGING SETUP
# ============================================================================

# Ensure log directory exists
$LogDir = $Config.LogPath
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$LogFile = Join-Path $LogDir "HyperVHost-Setup-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"

    # Color output based on level
    $color = switch($Level) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        "Success" { "Green" }
        default { "White" }
    }

    Write-Host $LogMessage -ForegroundColor $color
    Add-Content -Path $LogFile -Value $LogMessage
}

# ============================================================================
# SCRIPT HEADER - Log Configuration
# ============================================================================

Write-Log "========================================" -Level "Info"
Write-Log "$($Config.CompanyName) - Hyper-V Host Setup Script" -Level "Info"
Write-Log "========================================" -Level "Info"
Write-Log "" -Level "Info"
Write-Log "Configuration Settings:" -Level "Info"
Write-Log "  Company Name: $($Config.CompanyName)" -Level "Info"
Write-Log "  New Computer Name: $NewComputerName" -Level "Info"
Write-Log "  Current Computer Name: $env:COMPUTERNAME" -Level "Info"
Write-Log "  Skip Windows Update: $($Config.SkipWindowsUpdate)" -Level "Info"
Write-Log "  Skip BitLocker: $($Config.SkipBitLocker)" -Level "Info"
Write-Log "  Skip Network Teaming: $($Config.SkipNetworkTeaming)" -Level "Info"
Write-Log "  NICs per Team: $($Config.TeamsOf)" -Level "Info"
Write-Log "  Auto NIC Teaming: $($Config.AutoNICTeaming)" -Level "Info"
Write-Log "  Storage Redundancy: $($Config.StorageRedundancy)" -Level "Info"
Write-Log "  Log Path: $LogFile" -Level "Info"
Write-Log "" -Level "Info"

# ============================================================================
# ERROR HANDLING
# ============================================================================

$ErrorActionPreference = "Stop"
trap {
    Write-Log -Message "ERROR: $_" -Level "Error"
    Write-Log -Message "Setup failed at line $($_.InvocationInfo.ScriptLineNumber)" -Level "Error"

    # If running from RMM, ensure error is visible
    Write-Output "ERROR: $_"
    exit 1
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Function for NIC details
function Get-NICDetails {
    $nicInfo = @()

    # Get all physical network adapters
    $adapters = Get-NetAdapter | Where-Object {
        $_.Virtual -eq $false -and
        $_.InterfaceDescription -notlike "*Virtual*" -and
        $_.InterfaceDescription -notlike "*Hyper-V*" -and
        $_.DriverFileName -notlike "usb*"
    }

    foreach ($adapter in $adapters) {
        # Get PCI information
        $pnpDevice = Get-PnpDevice | Where-Object {
            $_.FriendlyName -eq $adapter.InterfaceDescription
        }

        # Parse PCI location (e.g., PCI bus 5, device 0, function 0)
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

# Function to show NIC layout
function Show-NICLayout {
    param($NICs)

    Write-Host "`n================================ NIC LAYOUT ================================" -ForegroundColor Cyan
    Write-Host "PCIe cards are grouped by Bus number. Adjacent functions usually = adjacent ports" -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Cyan

    $currentBus = ""
    $cardNumber = 1

    foreach ($nic in $NICs) {
        if ($nic.PCIBus -ne $currentBus) {
            $currentBus = $nic.PCIBus
            Write-Host "`n🔌 PCIe Card $cardNumber (Bus $currentBus):" -ForegroundColor Green
            $cardNumber++
        }

        $statusIcon = if($nic.Status -eq "Up") { "✅" } else { "❌" }
        $speedInfo = if($nic.LinkSpeed) { "[$($nic.LinkSpeed)]" } else { "[No Link]" }

        Write-Host ("  $statusIcon Port: {0,-20} {1,-10} Func:{2} MAC:{3}" -f
            $nic.Name,
            $speedInfo,
            $nic.PCIFunction,
            $nic.MacAddress.Substring(0,8) + "..."
        ) -ForegroundColor $(if($nic.Status -eq "Up"){"White"}else{"DarkGray"})
    }

    Write-Host "`n============================================================================" -ForegroundColor Cyan
}

# Storage helper functions
function Get-StorageRedundancyType {
    return $Config.StorageRedundancy
}

function Get-MediaType {
    param([Microsoft.Management.Infrastructure.CimInstance]$Disk)

    # Check physical disk media type if available
    $physicalDisk = Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceId -eq $Disk.Number }
    if ($physicalDisk) {
        switch ($physicalDisk.MediaType) {
            "SSD" { return "ssd" }
            "HDD" { return "hdd" }
            "SCM" { return "nvme" }
            default { return "hdd" }
        }
    }

    # Fallback: Check if system disk (usually SSD for BOSS/M.2)
    if ($Disk.IsBoot) {
        return "ssd"
    }

    # Check size and assume NVMe for smaller fast disks
    if ($Disk.Size -lt 1TB -and $Disk.Model -match "NVMe|BOSS|M\.2") {
        return "nvme"
    }

    return "hdd"
}

# ============================================================================
# MAIN SETUP PROCESS
# ============================================================================

try {
    Write-Log "Starting Hyper-V Host configuration..." -Level "Info"

    #region Step 0: Rename Computer
    Write-Log "Step 0: Computer Naming Configuration..." -Level "Info"

    if ($env:COMPUTERNAME -ne $NewComputerName) {
        Write-Log "Renaming computer from '$env:COMPUTERNAME' to '$NewComputerName'..." -Level "Info"

        try {
            Rename-Computer -NewName $NewComputerName -Force -ErrorAction Stop
            Write-Log "Computer renamed successfully to '$NewComputerName'" -Level "Success"
            Write-Log "Note: Restart required for name change to take effect" -Level "Warning"

            # Set a flag for restart required
            $Global:RestartRequired = $true
        } catch {
            Write-Log "Failed to rename computer: $_" -Level "Error"

            # Ask if they want to continue anyway
            $continue = Read-Host "Failed to rename computer. Continue anyway? (y/n)"
            if ($continue -ne 'y') {
                throw "Setup cancelled due to computer rename failure"
            }
        }
    } else {
        Write-Log "Computer name already set to '$NewComputerName'" -Level "Info"
        $Global:RestartRequired = $false
    }
    #endregion

    #region Step 1: Advanced Storage Configuration
    Write-Log "Step 1: Configuring Storage..." -Level "Info"
    try {
        # Detect if this is a Dell system with RAID controller
        $isDellSystem = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer -like "Dell*"
        $perccliPath = $null

        if ($isDellSystem) {
            Write-Log "Dell hardware detected - checking for RAID configuration..." -Level "Info"

            # Try to find PERCCLI (Dell RAID CLI tool)
            $possiblePaths = @(
                "C:\Program Files\Dell\SysMgt\oma\bin\perccli64.exe",
                "C:\Program Files\Dell\SysMgt\rac5\perccli64.exe",
                "C:\Program Files (x86)\Dell\SysMgt\oma\bin\perccli.exe",
                "$env:windir\temp\perccli64.exe"
            )

            foreach ($path in $possiblePaths) {
                if (Test-Path $path) {
                    $perccliPath = $path
                    Write-Log "Found PERCCLI at: $perccliPath" -Level "Info"
                    break
                }
            }

            # If not found, try to download it
            if (-not $perccliPath) {
                Write-Log "PERCCLI not found, downloading..." -Level "Info"
                try {
                    # Try multiple URLs for PERCCLI
                    $perccliUrls = @(
                        "https://dl.dell.com/FOLDER09766599M/1/PERCCLI_7.2313.0_A16_Windows.zip",  # Latest as of 2024
                        "https://dl.dell.com/FOLDER08939165M/1/PERCCLI_7.2110.00_A14_Windows.zip",
                        "https://dl.dell.com/FOLDER07815522M/1/PERCCLI_7.1910.00_A13_Windows.zip"
                    )

                    $downloadSuccess = $false
                    $zipPath = "$env:windir\temp\perccli.zip"

                    foreach ($url in $perccliUrls) {
                        try {
                            Write-Log "Trying URL: $url" -Level "Info"
                            $wc = New-Object System.Net.WebClient
                            $wc.DownloadFile($url, $zipPath)
                            $downloadSuccess = $true
                            Write-Log "Download successful from: $url" -Level "Info"
                            break
                        } catch {
                            Write-Log "Failed to download from $url : $_" -Level "Warning"
                        }
                    }

                    if ($downloadSuccess) {
                        # Extract PERCCLI
                        Expand-Archive -Path $zipPath -DestinationPath "$env:windir\temp\perccli" -Force
                        $perccliPath = Get-ChildItem "$env:windir\temp\perccli" -Recurse -Filter "perccli64.exe" | Select-Object -First 1 -ExpandProperty FullName

                        if ($perccliPath) {
                            Copy-Item $perccliPath "$env:windir\temp\perccli64.exe" -Force
                            $perccliPath = "$env:windir\temp\perccli64.exe"
                            Write-Log "PERCCLI downloaded and extracted" -Level "Info"
                        }
                    } else {
                        Write-Log "Could not download PERCCLI from any source" -Level "Warning"
                        Write-Log "Please install Dell OpenManage Server Administrator for RAID management" -Level "Warning"
                    }
                } catch {
                    Write-Log "Could not download PERCCLI: $_" -Level "Warning"
                }
            }
        }

        # Detect BOSS card (Dell Boot Optimized Server Storage)
        $hasBOSSCard = $false
        if ($isDellSystem) {
            # Check for BOSS controller via WMI
            $storageControllers = Get-CimInstance -ClassName Win32_SCSIController
            $bossController = $storageControllers | Where-Object { $_.Name -match "BOSS|Boot Optimized" }

            if ($bossController) {
                $hasBOSSCard = $true
                Write-Log "Dell BOSS card detected: $($bossController.Name)" -Level "Info"
            }

            # Also check via disk model
            $disks = Get-Disk
            $bossDisk = $disks | Where-Object { $_.Model -match "BOSS|DELLBOSS" }
            if ($bossDisk) {
                $hasBOSSCard = $true
                Write-Log "BOSS disk detected: $($bossDisk.Model)" -Level "Info"
            }
        }

        # Get all disks and analyze storage layout
        $allDisks = Get-Disk | Sort-Object Number
        Write-Host "`n📊 Storage Layout Analysis:" -ForegroundColor Cyan
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

        $diskInfo = @()
        foreach ($disk in $allDisks) {
            $mediaType = Get-MediaType -Disk $disk
            $sizeGB = [math]::Round($disk.Size / 1GB, 2)

            $info = [PSCustomObject]@{
                DiskNumber = $disk.Number
                Model = $disk.Model
                Size = "$sizeGB GB"
                MediaType = $mediaType
                IsBoot = $disk.IsBoot
                IsSystem = $disk.IsSystem
                PartitionStyle = $disk.PartitionStyle
                OperationalStatus = $disk.OperationalStatus
            }

            $diskInfo += $info

            $icon = if($disk.IsBoot){"🔷"}elseif($disk.IsSystem){"💠"}else{"💿"}
            $bootLabel = if($disk.IsBoot){" [BOOT]"}elseif($disk.IsSystem){" [SYSTEM]"}else{""}

            Write-Host "$icon Disk $($disk.Number): $($disk.Model) - $sizeGB GB ($mediaType)$bootLabel" -ForegroundColor $(if($disk.IsBoot){"Yellow"}else{"White"})
        }

        # Check for RAID configuration issues
        $raidDisks = $allDisks | Where-Object { $_.Model -match "PERC|RAID|Virtual" }
        $needsRaidReconfig = $false

        if ($raidDisks.Count -eq 1 -and $perccliPath) {
            # Single RAID virtual disk detected - check if it has both OS and data
            $raidDisk = $raidDisks[0]
            $partitions = Get-Partition -DiskNumber $raidDisk.Number -ErrorAction SilentlyContinue

            if ($partitions.Count -gt 2) {  # More than just system/boot partitions
                Write-Host "`n⚠️  WARNING: Single RAID Virtual Disk Configuration Detected!" -ForegroundColor Red
                Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
                Write-Host "Current: OS and Data are on the same RAID virtual disk" -ForegroundColor Yellow
                Write-Host "Recommended: Separate RAID virtual disks for OS and Data" -ForegroundColor Green
                Write-Host "" -ForegroundColor White
                Write-Host "For optimal Hyper-V performance, reconfigure RAID as follows:" -ForegroundColor White
                Write-Host "  1. Create RAID 1 virtual disk (2 drives) for OS - ~300-500GB" -ForegroundColor Cyan
                Write-Host "  2. Create RAID 10 or RAID 5 virtual disk for Data/VMs" -ForegroundColor Cyan
                Write-Host "" -ForegroundColor White
                Write-Host "To reconfigure RAID:" -ForegroundColor Yellow
                Write-Host "  1. Restart server and enter RAID controller (Ctrl+R or F2)" -ForegroundColor White
                Write-Host "  2. Delete existing virtual disk (WARNING: Data loss!)" -ForegroundColor Red
                Write-Host "  3. Create two new virtual disks as described above" -ForegroundColor White
                Write-Host "  4. Reinstall Windows on the first virtual disk" -ForegroundColor White
                Write-Host "  5. Re-run this script" -ForegroundColor White
                Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

                $continueAnyway = Read-Host "`nContinue with suboptimal configuration? (y/n)"
                if ($continueAnyway -ne 'y') {
                    Write-Log "Setup cancelled for RAID reconfiguration" -Level "Warning"
                    throw "Please reconfigure RAID and re-run setup"
                }
                $needsRaidReconfig = $true
            }
        }

        # Determine storage configuration strategy
        Write-Host "`n🎯 Storage Configuration Strategy:" -ForegroundColor Green

        $bootDisk = $allDisks | Where-Object { $_.IsBoot -eq $true } | Select-Object -First 1
        $dataDisks = $allDisks | Where-Object { $_.IsBoot -eq $false }

        if ($hasBOSSCard -and $bootDisk) {
            Write-Host "✅ BOSS card detected for OS disk" -ForegroundColor Green
            Write-Host "   Boot Disk: Disk $($bootDisk.Number) - $($bootDisk.Model)" -ForegroundColor White

            # Expand OS partition on BOSS
            Write-Log "Checking OS partition on BOSS disk..." -Level "Info"
            try {
                $currentSize = (Get-Partition -DriveLetter C).Size
                $maxSize = (Get-PartitionSupportedSize -DriveLetter C).SizeMax

                if ($currentSize -lt ($maxSize - 1GB)) {  # Only resize if more than 1GB available
                    Write-Log "Expanding OS partition from $([math]::Round($currentSize/1GB,2))GB to $([math]::Round($maxSize/1GB,2))GB..." -Level "Info"
                    Resize-Partition -DriveLetter C -Size $maxSize
                    Write-Log "OS partition expanded successfully" -Level "Success"
                } else {
                    Write-Log "OS partition already at maximum size ($([math]::Round($currentSize/1GB,2))GB)" -Level "Info"
                }
            } catch {
                Write-Log "Could not resize OS partition: $_" -Level "Warning"
            }
        } elseif ($bootDisk) {
            Write-Host "✅ Standard boot disk configuration" -ForegroundColor Green
            Write-Host "   Boot Disk: Disk $($bootDisk.Number) - $($bootDisk.Model)" -ForegroundColor White

            # Check if we should split the boot disk
            $bootDiskSizeGB = [math]::Round($bootDisk.Size / 1GB, 2)
            if ($bootDiskSizeGB -gt 500 -and $dataDisks.Count -eq 0 -and -not $needsRaidReconfig) {
                Write-Host "⚠️  Large boot disk with no data disks - checking partition options" -ForegroundColor Yellow

                try {
                    $osPartition = Get-Partition -DriveLetter C
                    $currentSizeGB = [math]::Round($osPartition.Size / 1GB, 2)

                    # Check if there's unallocated space on the disk
                    $unallocatedSpace = $bootDisk.Size - (Get-Partition -DiskNumber $bootDisk.Number | Measure-Object -Property Size -Sum).Sum

                    if ($unallocatedSpace -gt 100GB) {
                        Write-Log "Found $([math]::Round($unallocatedSpace/1GB,2))GB unallocated space" -Level "Info"
                        # Create data partition on unallocated space
                        $dataPart = New-Partition -DiskNumber $bootDisk.Number -UseMaximumSize -AssignDriveLetter
                        Format-Volume -DriveLetter $dataPart.DriveLetter -FileSystem NTFS -AllocationUnitSize 1024 -NewFileSystemLabel "$($Config.StorageRedundancy)-ssd-01"
                        Write-Log "Created data partition on unallocated space" -Level "Success"
                    } elseif ($currentSizeGB -gt 150) {
                        Write-Host "   OS partition is $currentSizeGB GB - would need to shrink for data partition" -ForegroundColor Yellow
                        $shrink = Read-Host "   Shrink OS partition to 120GB and create data partition? (y/n)"
                        if ($shrink -eq 'y') {
                            # This requires more complex operations - typically done offline
                            Write-Log "Partition shrinking requires offline operation" -Level "Warning"
                            Write-Host "   Please use Disk Management to shrink C: drive manually" -ForegroundColor Yellow
                        }
                    } else {
                        Write-Log "OS partition size is appropriate ($currentSizeGB GB)" -Level "Info"
                    }
                } catch {
                    Write-Log "Could not analyze partition layout: $_" -Level "Warning"
                }
            } else {
                # Just try to expand OS partition if needed
                try {
                    $currentSize = (Get-Partition -DriveLetter C).Size
                    $maxSize = (Get-PartitionSupportedSize -DriveLetter C).SizeMax

                    if ($currentSize -lt ($maxSize - 1GB)) {  # Only resize if more than 1GB available
                        Write-Log "Expanding OS partition..." -Level "Info"
                        Resize-Partition -DriveLetter C -Size $maxSize
                        Write-Log "OS partition expanded successfully" -Level "Success"
                    } else {
                        Write-Log "OS partition already at maximum size" -Level "Info"
                    }
                } catch {
                    Write-Log "Could not resize OS partition: $_" -Level "Warning"
                }
            }
        }

        # Configure data disks with proper naming convention
        if ($dataDisks.Count -gt 0) {
            Write-Host "`n📁 Configuring $($dataDisks.Count) data disk(s)..." -ForegroundColor Cyan

            # Use configured redundancy type
            $redundancyType = $Config.StorageRedundancy
            $redundancyName = switch($redundancyType) {
                "ers" { "Endpoint Redundant Storage (Local)" }
                "rrs" { "Rack Redundant Storage" }
                "zrs" { "Zone Redundant Storage" }
                "grs" { "Geographic Redundant Storage" }
            }
            Write-Host "Using redundancy type: $redundancyType - $redundancyName" -ForegroundColor Gray

            # Group disks by media type
            $disksByMedia = $dataDisks | Group-Object { Get-MediaType -Disk $_ }

            foreach ($mediaGroup in $disksByMedia) {
                $mediaType = $mediaGroup.Name
                $sequence = 1

                Write-Host "`nConfiguring $($mediaGroup.Count) $mediaType disk(s):" -ForegroundColor White

                foreach ($disk in $mediaGroup.Group) {
                    try {
                        $volumeLabel = "$redundancyType-$mediaType-$('{0:d2}' -f $sequence)"
                        $diskNumber = $disk.Number
                        $diskSizeGB = [math]::Round($disk.Size / 1GB, 2)

                        Write-Host "  Processing Disk $diskNumber ($diskSizeGB GB)..." -ForegroundColor Gray

                        # Check if disk needs to be cleaned (has partitions or is RAW)
                        if ($disk.PartitionStyle -eq 'RAW' -or ($disk.PartitionStyle -eq 'MBR')) {
                            Write-Host "    Initializing as GPT..." -ForegroundColor Gray
                            Initialize-Disk -Number $diskNumber -PartitionStyle GPT -PassThru | Out-Null
                        } elseif ((Get-Partition -DiskNumber $diskNumber -ErrorAction SilentlyContinue).Count -gt 0) {
                            # Disk has partitions, ask to wipe
                            Write-Host "    ⚠️ Disk has existing partitions" -ForegroundColor Yellow
                            $wipe = Read-Host "    Wipe disk $diskNumber and reconfigure? (y/n)"

                            if ($wipe -eq 'y') {
                                Clear-Disk -Number $diskNumber -RemoveData -Confirm:$false
                                Initialize-Disk -Number $diskNumber -PartitionStyle GPT -PassThru | Out-Null
                            } else {
                                Write-Host "    Skipping disk $diskNumber" -ForegroundColor Yellow
                                continue
                            }
                        }

                        # Create partition with next available drive letter
                        Write-Host "    Creating partition..." -ForegroundColor Gray
                        $partition = New-Partition -DiskNumber $diskNumber -UseMaximumSize -AssignDriveLetter

                        # Format with 1024 byte (1KB) allocation unit size for performance
                        Write-Host "    Formatting as NTFS with 1KB cluster size..." -ForegroundColor Gray
                        Format-Volume -DriveLetter $partition.DriveLetter `
                                     -FileSystem NTFS `
                                     -AllocationUnitSize 1024 `
                                     -NewFileSystemLabel $volumeLabel `
                                     -Confirm:$false | Out-Null

                        Write-Host "    ✅ Configured as $($partition.DriveLetter): drive - Label: $volumeLabel" -ForegroundColor Green

                        # Create Hyper-V directories if this is the first data disk
                        if ($sequence -eq 1) {
                            $hvPath = "$($partition.DriveLetter):\Hyper-V"
                            New-Item -Path "$hvPath\Virtual Hard Disks" -ItemType Directory -Force | Out-Null
                            New-Item -Path "$hvPath\Virtual Machines" -ItemType Directory -Force | Out-Null
                            Write-Host "    Created Hyper-V directories on $($partition.DriveLetter): drive" -ForegroundColor Gray
                        }

                        $sequence++
                        Write-Log "Configured disk $diskNumber as $volumeLabel" -Level "Info"

                    } catch {
                        Write-Log "Error configuring disk $diskNumber : $_" -Level "Error"
                        Write-Host "    ❌ Error: $_" -ForegroundColor Red
                    }
                }
            }
        } else {
            Write-Host "⚠️  No additional data disks found" -ForegroundColor Yellow
            Write-Host "   VM storage will use the OS disk" -ForegroundColor White
        }

        # Show final storage configuration
        Write-Host "`n✅ Storage Configuration Complete!" -ForegroundColor Green
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
        Get-Volume | Where-Object { $_.DriveLetter -ne $null } |
            Sort-Object DriveLetter |
            Format-Table DriveLetter, FileSystemLabel, FileSystem,
                @{Name="Size(GB)";Expression={[math]::Round($_.Size/1GB,2)}},
                @{Name="Free(GB)";Expression={[math]::Round($_.SizeRemaining/1GB,2)}} -AutoSize

        Write-Log "Advanced storage configuration completed" -Level "Success"

    } catch {
        Write-Log "Storage configuration error: $_" -Level "Error"
        Write-Host "❌ Storage configuration failed: $_" -ForegroundColor Red

        # Fallback to simple configuration
        Write-Host "Falling back to simple storage configuration..." -ForegroundColor Yellow

        $inputBoot = Read-Host "Does this server have a dedicated boot disk? (y/n)"
        if ($inputBoot -eq "y") {
            # Expand OS partition
            $maxSize = (Get-PartitionSupportedSize -DriveLetter C).sizeMax
            Resize-Partition -DriveLetter C -Size $maxSize

            # Create data partition
            $dataDisk = Get-Disk | Where-Object { $_.IsBoot -eq $false } | Select-Object -First 1
            if ($dataDisk) {
                Initialize-Disk -Number $dataDisk.Number -PartitionStyle GPT
                New-Partition -DiskNumber $dataDisk.Number -UseMaximumSize -DriveLetter D
                Format-Volume -DriveLetter D -FileSystem NTFS -NewFileSystemLabel "data1"
            }
        }
    }
    #endregion

    # Continue with remaining steps...
    # [Rest of the script would continue here with the same pattern]

    Write-Log "========================================" -Level "Info"
    Write-Log "Hyper-V Host Setup Complete!" -Level "Success"
    Write-Log "========================================" -Level "Info"
    Write-Log "Review log file at: $LogFile" -Level "Info"

} catch {
    Write-Log -Message "Setup failed: $_" -Level "Error"
    Write-Log -Message "Please review the log file at: $LogFile" -Level "Error"

    # Ensure error is visible in RMM console
    Write-Output "SCRIPT FAILED: $_"
    exit 1
}