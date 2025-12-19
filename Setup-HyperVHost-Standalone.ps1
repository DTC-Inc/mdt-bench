<#
.SYNOPSIS
    Complete Standalone Hyper-V Host Setup Script
.DESCRIPTION
    Single-file setup script for Hyper-V host servers with all configurations
    consolidated. No external script dependencies.
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
    [int]$TeamsOf = 2,  # Team NICs in groups of 2 (default) or 4

    [Parameter()]
    [switch]$AutoNICTeaming,  # Auto-team by PCIe card instead of interactive

    [Parameter()]
    [ValidateSet("ers", "rrs", "zrs", "grs")]
    [string]$StorageRedundancy = "ers",  # Default to Endpoint Redundant Storage

    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\Logs\HyperVHost-Standalone-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"
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

# Helper function for NIC details
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

# Helper function to show NIC layout
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
    Write-Log "Starting Hyper-V Host Standalone Setup" -Level "Info"
    Write-Log "========================================" -Level "Info"

    #region Advanced Storage Configuration with Dell RAID Detection
    Write-Log "Step 1: Advanced Storage Configuration..." -Level "Info"
    try {
        # Storage naming convention functions
        function Get-StorageRedundancyType {
            param([string]$Prompt = "Select storage redundancy type")
            Write-Host "`n$Prompt:" -ForegroundColor Cyan
            Write-Host "1. ERS - Endpoint Redundant Storage (Local redundancy)" -ForegroundColor White
            Write-Host "2. RRS - Rack Redundant Storage (Rack-level redundancy)" -ForegroundColor White
            Write-Host "3. ZRS - Zone Redundant Storage (Datacenter zone redundancy)" -ForegroundColor White
            Write-Host "4. GRS - Geographic Redundant Storage (Multi-site redundancy)" -ForegroundColor White

            $selection = Read-Host "Enter choice (1-4)"
            switch ($selection) {
                "1" { return "ers" }
                "2" { return "rrs" }
                "3" { return "zrs" }
                "4" { return "grs" }
                default { return "ers" }
            }
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
                    $perccliUrl = "https://dl.dell.com/FOLDER08939165M/1/PERCCLI_7.2110.00_A14_Windows.zip"
                    $zipPath = "$env:windir\temp\perccli.zip"

                    $wc = New-Object System.Net.WebClient
                    $wc.DownloadFile($perccliUrl, $zipPath)

                    # Extract PERCCLI
                    Expand-Archive -Path $zipPath -DestinationPath "$env:windir\temp\perccli" -Force
                    $perccliPath = Get-ChildItem "$env:windir\temp\perccli" -Recurse -Filter "perccli64.exe" | Select-Object -First 1 -ExpandProperty FullName

                    if ($perccliPath) {
                        Copy-Item $perccliPath "$env:windir\temp\perccli64.exe" -Force
                        $perccliPath = "$env:windir\temp\perccli64.exe"
                        Write-Log "PERCCLI downloaded and extracted" -Level "Info"
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

        # If PERCCLI is available, get RAID info
        $raidVolumes = @()
        if ($perccliPath) {
            Write-Host "`n🔧 Checking RAID configuration..." -ForegroundColor Cyan
            try {
                $raidOutput = & $perccliPath /c0 show
                # Parse RAID configuration (simplified - would need more complex parsing in production)
                Write-Log "RAID configuration detected via PERCCLI" -Level "Info"
            } catch {
                Write-Log "Could not query RAID configuration: $_" -Level "Warning"
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
            Write-Log "Expanding OS partition on BOSS disk..." -Level "Info"
            $maxSize = (Get-PartitionSupportedSize -DriveLetter C).sizeMax
            Resize-Partition -DriveLetter C -Size $maxSize
        } elseif ($bootDisk) {
            Write-Host "✅ Standard boot disk configuration" -ForegroundColor Green
            Write-Host "   Boot Disk: Disk $($bootDisk.Number) - $($bootDisk.Model)" -ForegroundColor White

            # Check if we should split the boot disk
            $bootDiskSizeGB = [math]::Round($bootDisk.Size / 1GB, 2)
            if ($bootDiskSizeGB -gt 500 -and $dataDisks.Count -eq 0) {
                Write-Host "⚠️  Large boot disk with no data disks - will partition for data" -ForegroundColor Yellow

                # Resize OS partition to 120GB if large disk
                Resize-Partition -DriveLetter C -Size 120GB

                # Create data partition on remaining space
                $dataPart = New-Partition -DiskNumber $bootDisk.Number -UseMaximumSize -AssignDriveLetter
                Format-Volume -DriveLetter $dataPart.DriveLetter -FileSystem NTFS -AllocationUnitSize 1024 -NewFileSystemLabel "ers-ssd-01"
            } else {
                # Just expand OS partition
                $maxSize = (Get-PartitionSupportedSize -DriveLetter C).sizeMax
                Resize-Partition -DriveLetter C -Size $maxSize
            }
        }

        # Configure data disks with proper naming convention
        if ($dataDisks.Count -gt 0) {
            Write-Host "`n📁 Configuring $($dataDisks.Count) data disk(s)..." -ForegroundColor Cyan

            # Use the specified or default redundancy type
            $redundancyType = $StorageRedundancy
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

        Write-Log "Advanced storage configuration completed" -Level "Info"

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

    #region Enhanced Hyper-V SET Network Configuration
    Write-Log "Step 3: Configuring Hyper-V Switch Embedded Teams (SET)..." -Level "Info"
    if (!$SkipNetworkTeaming) {
        try {
            # Clean up existing teams first
            Write-Host "`nCleaning up existing virtual switches..." -ForegroundColor Yellow
            Get-VMNetworkAdapter -ManagementOS -ErrorAction SilentlyContinue | Where-Object -Property "Name" -NotLike "Container NIC*" | Remove-VMNetworkAdapter -ErrorAction SilentlyContinue
            Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object -Property Name -NotLike "Default Switch" | Remove-VMSwitch -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5

            # Get and display NIC information
            Write-Host "`nScanning for network adapters..." -ForegroundColor Cyan
            $allNICs = Get-NICDetails

            if ($allNICs.Count -eq 0) {
                Write-Log "No suitable network adapters found!" -Level "Error"
                Write-Log "Skipping network teaming configuration" -Level "Warning"
            } else {
                Write-Log "Found $($allNICs.Count) network adapters"
                Show-NICLayout -NICs $allNICs

                # Group NICs by PCIe card (bus number)
                $nicsByCard = $allNICs | Group-Object -Property PCIBus

                Write-Host "`n📊 Summary:" -ForegroundColor Cyan
                Write-Host "  - Total NICs: $($allNICs.Count)" -ForegroundColor White
                Write-Host "  - PCIe Cards: $($nicsByCard.Count)" -ForegroundColor White
                Write-Host "  - Team Size: $TeamsOf NICs per team" -ForegroundColor White
                Write-Host "  - Mode: $(if($AutoNICTeaming){'Auto (by PCIe card)'}else{'Interactive (verify adjacency)'})" -ForegroundColor White

                $teamNumber = 1

                if ($AutoNICTeaming) {
                    Write-Host "`n🤖 AUTO MODE: Creating SET teams by PCIe card..." -ForegroundColor Green

                    foreach ($cardGroup in $nicsByCard) {
                        $cardNICs = $cardGroup.Group | Where-Object { $_.Status -eq "Up" } | Sort-Object PCIFunction

                        if ($cardNICs.Count -ge $TeamsOf) {
                            # Create teams of specified size from this card
                            for ($i = 0; $i -lt $cardNICs.Count; $i += $TeamsOf) {
                                $teamNICs = $cardNICs[$i..([Math]::Min($i + $TeamsOf - 1, $cardNICs.Count - 1))]

                                if ($teamNICs.Count -eq $TeamsOf) {
                                    $teamName = "SET$teamNumber"
                                    Write-Host "`nCreating $teamName with $TeamsOf NICs:" -ForegroundColor Green
                                    foreach ($nic in $teamNICs) {
                                        Write-Host "  - $($nic.Name) [Bus:$($nic.PCIBus) Func:$($nic.PCIFunction)]" -ForegroundColor White
                                    }

                                    if ($teamNumber -eq 1) {
                                        # First team gets management OS access
                                        New-VMSwitch -Name $teamName -NetAdapterName $teamNICs.Name -EnableEmbeddedTeaming $true
                                        Rename-VMNetworkAdapter -Name $teamName -NewName "vNIC1-$teamName" -ManagementOS
                                        Add-VMNetworkAdapter -Name "vNIC2-$teamName" -SwitchName $teamName -ManagementOS
                                    } else {
                                        # Additional teams typically for VM traffic only
                                        New-VMSwitch -Name $teamName -NetAdapterName $teamNICs.Name -EnableEmbeddedTeaming $true -AllowManagementOS $false
                                    }

                                    Write-Log "Created SET team: $teamName" -Level "Info"
                                    $teamNumber++
                                }
                            }
                        } else {
                            Write-Log "Card on Bus $($cardGroup.Name) has insufficient NICs ($($cardNICs.Count) < $TeamsOf)" -Level "Warning"
                        }
                    }
                } else {
                    Write-Host "`n👤 INTERACTIVE MODE - Ensuring physically adjacent ports are teamed" -ForegroundColor Green
                    $continue = $true

                    while ($continue) {
                        Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
                        Write-Host "Setting up SET Team #$teamNumber" -ForegroundColor Cyan
                        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

                        Write-Host "`nINSTRUCTIONS:" -ForegroundColor Yellow
                        Write-Host "1. Disconnect all cables" -ForegroundColor White
                        Write-Host "2. Connect ONLY the $TeamsOf ports you want in SET Team #$teamNumber" -ForegroundColor White
                        Write-Host "3. For best performance, use adjacent ports on the same PCIe card" -ForegroundColor White
                        Write-Host "4. Check the PCIe Bus number above to identify same-card ports" -ForegroundColor White

                        $ready = Read-Host "`nType 'r' when cables are connected"
                        while ($ready -ne 'r') {
                            Write-Host "Waiting for cable connections..." -ForegroundColor DarkGray
                            $ready = Read-Host "Type 'r' when ready"
                        }

                        # Wait for link state to stabilize
                        Write-Host "Waiting for link state to stabilize..." -ForegroundColor Yellow
                        Start-Sleep -Seconds 5

                        # Rescan for connected NICs
                        $connectedNICs = Get-NICDetails | Where-Object { $_.Status -eq "Up" }

                        if ($connectedNICs.Count -eq 0) {
                            Write-Host "❌ No connected NICs found! Please check cable connections." -ForegroundColor Red
                            continue
                        }

                        Write-Host "`n✅ Found $($connectedNICs.Count) connected NICs:" -ForegroundColor Green
                        Show-NICLayout -NICs $connectedNICs

                        if ($connectedNICs.Count -eq $TeamsOf) {
                            $confirm = Read-Host "`nCreate SET team with these $TeamsOf NICs? (y/n)"

                            if ($confirm -eq 'y') {
                                $teamName = "SET$teamNumber"

                                if ($teamNumber -eq 1) {
                                    # First team gets management OS access
                                    New-VMSwitch -Name $teamName -NetAdapterName $connectedNICs.Name -EnableEmbeddedTeaming $true
                                    Rename-VMNetworkAdapter -Name $teamName -NewName "vNIC1-$teamName" -ManagementOS
                                    Add-VMNetworkAdapter -Name "vNIC2-$teamName" -SwitchName $teamName -ManagementOS
                                } else {
                                    # Additional teams for VM traffic only
                                    New-VMSwitch -Name $teamName -NetAdapterName $connectedNICs.Name -EnableEmbeddedTeaming $true -AllowManagementOS $false
                                }

                                Write-Log "Created SET team: $teamName" -Level "Info"
                                $teamNumber++
                            }
                        } else {
                            Write-Host "⚠️  Warning: Expected $TeamsOf NICs but found $($connectedNICs.Count)" -ForegroundColor Yellow
                            $proceed = Read-Host "Create team anyway? (y/n)"

                            if ($proceed -eq 'y') {
                                $teamName = "SET$teamNumber"

                                if ($teamNumber -eq 1) {
                                    New-VMSwitch -Name $teamName -NetAdapterName $connectedNICs.Name -EnableEmbeddedTeaming $true
                                    Rename-VMNetworkAdapter -Name $teamName -NewName "vNIC1-$teamName" -ManagementOS
                                    Add-VMNetworkAdapter -Name "vNIC2-$teamName" -SwitchName $teamName -ManagementOS
                                } else {
                                    New-VMSwitch -Name $teamName -NetAdapterName $connectedNICs.Name -EnableEmbeddedTeaming $true -AllowManagementOS $false
                                }

                                Write-Log "Created SET team: $teamName with $($connectedNICs.Count) NICs" -Level "Info"
                                $teamNumber++
                            }
                        }

                        $more = Read-Host "`nCreate another SET team? (y/n)"
                        $continue = ($more -eq 'y')
                    }
                }

                # Show final configuration
                if ($teamNumber -gt 1) {
                    Write-Host "`n✅ SET Team Configuration Complete!" -ForegroundColor Green
                    Write-Host "Created $($teamNumber - 1) SET team(s)" -ForegroundColor White
                    Write-Host "`nFinal Configuration:" -ForegroundColor Cyan
                    Get-VMSwitch | Format-Table Name, SwitchType, NetAdapterInterfaceDescription
                }
            }

            Write-Log "Network configuration completed" -Level "Info"
        } catch {
            Write-Log "Network configuration error: $_" -Level "Warning"
        }
    } else {
        Write-Log "Skipping network teaming configuration (per parameter)" -Level "Info"
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
    if (!$SkipWindowsUpdate) {
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
        Write-Log "Step 9: Skipping Windows Updates (per parameter)" -Level "Info"
    }
    #endregion

    #region Hyper-V Specific Configuration
    Write-Log "Step 10: Configuring Hyper-V Settings..." -Level "Info"
    try {
        # Install Hyper-V if not already installed
        $hyperVFeature = Get-WindowsFeature -Name Hyper-V
        if ($hyperVFeature.InstallState -ne "Installed") {
            Write-Log "Installing Hyper-V role..." -Level "Info"
            Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart
        }

        # Configure Hyper-V storage paths
        if (Test-Path D:\) {
            Set-VMHost -virtualHardDiskPath "D:\Virtual Hard Disks"
            Set-VMHost -virtualMachinePath "D:\"
            Write-Log "Hyper-V storage paths configured" -Level "Info"
        } else {
            Write-Log "D:\ drive not found, using default Hyper-V paths" -Level "Warning"
        }

        Write-Log "Hyper-V configuration completed" -Level "Info"
    } catch {
        Write-Log "Hyper-V configuration error: $_" -Level "Warning"
    }
    #endregion

    #region BitLocker Configuration
    if (!$SkipBitLocker) {
        Write-Log "Step 11: Configuring BitLocker..." -Level "Info"
        try {
            # Enable BitLocker on OS drive
            Get-BitlockerVolume | Where -Property VolumeType -eq OperatingSystem | Enable-Bitlocker -TpmProtector -EncryptionMethod AES256
            Get-BitlockerVolume | Where -Property VolumeType -eq OperatingSystem | Add-BitlockerKeyProtector -RecoveryPasswordProtector

            # Enable BitLocker on data drives
            Get-BitlockerVolume | Where -Property VolumeType -ne OperatingSystem | Enable-Bitlocker -StartupKeyProtector -StartupKeyPath $Env:SYSTEMDRIVE\
            Get-BitlockerVolume | Where -Property VolumeType -ne OperatingSystem | Add-BitlockerKeyProtector -RecoveryPasswordProtector
            Get-BitlockerVolume | Where -Property VolumeType -ne OperatingSystem | Enable-BitLockerAutoUnlock

            Write-Log "BitLocker configuration completed" -Level "Info"
        } catch {
            Write-Log "BitLocker configuration error: $_" -Level "Warning"
        }
    } else {
        Write-Log "Step 11: Skipping BitLocker configuration (per parameter)" -Level "Info"
    }
    #endregion

    Write-Log "========================================" -Level "Info"
    Write-Log "Hyper-V Host Setup Completed Successfully!" -Level "Info"
    Write-Log "========================================" -Level "Info"
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