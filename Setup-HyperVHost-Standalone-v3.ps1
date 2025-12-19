<#
.SYNOPSIS
    Complete Standalone Hyper-V Host Setup Script - MSP RMM Template Version
.DESCRIPTION
    Single-file setup script for Hyper-V host servers following MSP Script Library standards.
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

$ScriptLogName = "HyperVHost-Setup-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').log"
$ServerRole = "HV"  # Hyper-V Host role code

# Default configuration values
$Config = @{
    ServerSequence = ""
    SkipWindowsUpdate = $false
    SkipBitLocker = $false
    SkipNetworkTeaming = $false
    TeamsOf = 2
    AutoNICTeaming = $false
    StorageRedundancy = "ers"
    CompanyName = "DTC"
    AcceptRAIDWarning = $false
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
    Write-Host "Hyper-V Host Setup - Interactive Mode" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    # Server sequence (REQUIRED)
    $ValidInput = 0
    while ($ValidInput -ne 1) {
        Write-Host "`nServer Naming Configuration" -ForegroundColor Yellow
        Write-Host "Server will be named: ${ServerRole}XX (e.g., HV01, HV02)" -ForegroundColor Gray
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

    $skipBitLocker = Read-Host "Skip BitLocker configuration? (y/n, default: n)"
    $Config.SkipBitLocker = ($skipBitLocker -eq 'y')

    $skipTeaming = Read-Host "Skip network teaming? (y/n, default: n)"
    $Config.SkipNetworkTeaming = ($skipTeaming -eq 'y')

    if (-not $Config.SkipNetworkTeaming) {
        $teamsOf = Read-Host "NICs per team - 2 or 4? (default: 2)"
        if ($teamsOf -eq "4") { $Config.TeamsOf = 4 }

        $autoTeam = Read-Host "Auto-configure teams by PCIe card? (y/n, default: n)"
        $Config.AutoNICTeaming = ($autoTeam -eq 'y')
    }

    $redundancy = Read-Host "Storage redundancy type (ers/rrs/zrs/grs, default: ers)"
    if ($redundancy -in @("ers", "rrs", "zrs", "grs")) {
        $Config.StorageRedundancy = $redundancy
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
    $Config.SkipBitLocker = if ($null -ne $SkipBitLocker) { $SkipBitLocker } else { $false }
    $Config.SkipNetworkTeaming = if ($null -ne $SkipNetworkTeaming) { $SkipNetworkTeaming } else { $false }
    $Config.TeamsOf = if ($null -ne $TeamsOf -and $TeamsOf -in @(2,4)) { $TeamsOf } else { 2 }
    $Config.AutoNICTeaming = if ($null -ne $AutoNICTeaming) { $AutoNICTeaming } else { $false }
    $Config.StorageRedundancy = if ($null -ne $StorageRedundancy -and $StorageRedundancy -in @("ers","rrs","zrs","grs")) { $StorageRedundancy } else { "ers" }
    $Config.CompanyName = if ($null -ne $CompanyName) { $CompanyName } else { "DTC" }
    $Config.AcceptRAIDWarning = if ($null -ne $AcceptRAIDWarning) { $AcceptRAIDWarning } else { $false }

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
# SECTION 2: HELPER FUNCTIONS (Non-interactive versions)
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

# Get user input or use default (RMM-aware)
function Get-UserChoice {
    param(
        [string]$Prompt,
        [string]$Default = "n",
        [string]$RMMVariable = $null
    )

    if ($Config.NonInteractive) {
        # In RMM mode, use the RMM variable value or default
        if ($RMMVariable) {
            return $RMMVariable
        }
        return $Default
    } else {
        # In interactive mode, prompt the user
        return Read-Host $Prompt
    }
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

# ============================================================================
# SECTION 3: MAIN SCRIPT LOGIC
# ============================================================================

Start-Transcript -Path $LogPath

try {
    Write-ScriptLog "========================================" -Level "Info"
    Write-ScriptLog "$($Config.CompanyName) - Hyper-V Host Setup Script (v3.0)" -Level "Info"
    Write-ScriptLog "========================================" -Level "Info"
    Write-ScriptLog "" -Level "Info"
    Write-ScriptLog "Configuration Settings:" -Level "Info"
    Write-ScriptLog "  RMM Mode: $($RMM -eq 1)" -Level "Info"
    Write-ScriptLog "  Company Name: $($Config.CompanyName)" -Level "Info"
    Write-ScriptLog "  New Computer Name: $NewComputerName" -Level "Info"
    Write-ScriptLog "  Current Computer Name: $env:COMPUTERNAME" -Level "Info"
    Write-ScriptLog "  Skip Windows Update: $($Config.SkipWindowsUpdate)" -Level "Info"
    Write-ScriptLog "  Skip BitLocker: $($Config.SkipBitLocker)" -Level "Info"
    Write-ScriptLog "  Skip Network Teaming: $($Config.SkipNetworkTeaming)" -Level "Info"
    Write-ScriptLog "  NICs per Team: $($Config.TeamsOf)" -Level "Info"
    Write-ScriptLog "  Auto NIC Teaming: $($Config.AutoNICTeaming)" -Level "Info"
    Write-ScriptLog "  Storage Redundancy: $($Config.StorageRedundancy)" -Level "Info"
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

    #region Step 1: Advanced Storage Configuration
    Write-ScriptLog "Step 1: Configuring Storage..." -Level "Info"

    # Check if this is a Dell system
    $isDellSystem = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer -like "Dell*"
    $perccliPath = $null

    if ($isDellSystem) {
        Write-ScriptLog "Dell hardware detected - checking for RAID configuration..." -Level "Info"

        # Try to find PERCCLI
        $possiblePaths = @(
            "C:\Program Files\Dell\SysMgt\oma\bin\perccli64.exe",
            "C:\Program Files\Dell\SysMgt\rac5\perccli64.exe",
            "$env:windir\temp\perccli64.exe"
        )

        foreach ($path in $possiblePaths) {
            if (Test-Path $path) {
                $perccliPath = $path
                Write-ScriptLog "Found PERCCLI at: $perccliPath" -Level "Info"
                break
            }
        }

        if (-not $perccliPath -and -not $Config.NonInteractive) {
            Write-ScriptLog "PERCCLI not found - RAID detection limited" -Level "Warning"
        }
    }

    # Get all disks and analyze
    $allDisks = Get-Disk | Sort-Object Number
    Write-ScriptLog "Found $($allDisks.Count) disk(s)" -Level "Info"

    # Check for RAID configuration issues
    $raidDisks = $allDisks | Where-Object { $_.Model -match "PERC|RAID|Virtual" }
    $needsRaidReconfig = $false

    if ($raidDisks.Count -eq 1) {
        $raidDisk = $raidDisks[0]
        $partitions = Get-Partition -DiskNumber $raidDisk.Number -ErrorAction SilentlyContinue

        if ($partitions.Count -gt 2) {
            Write-ScriptLog "WARNING: Single RAID Virtual Disk Configuration Detected!" -Level "Warning"
            Write-ScriptLog "Current: OS and Data are on the same RAID virtual disk" -Level "Warning"
            Write-ScriptLog "Recommended: Separate RAID virtual disks for OS and Data" -Level "Warning"

            if ($Config.NonInteractive) {
                if (-not $Config.AcceptRAIDWarning) {
                    Write-ScriptLog "Single RAID disk detected and AcceptRAIDWarning not set!" -Level "Error"
                    Write-ScriptLog "Set `$AcceptRAIDWarning=`$true in RMM to continue with this configuration" -Level "Error"
                    throw "RAID reconfiguration recommended. Set AcceptRAIDWarning=true to continue."
                }
                Write-ScriptLog "Continuing with single RAID disk (AcceptRAIDWarning=true)" -Level "Warning"
            } else {
                $continueAnyway = Read-Host "Continue with suboptimal configuration? (y/n)"
                if ($continueAnyway -ne 'y') {
                    throw "Please reconfigure RAID and re-run setup"
                }
            }
            $needsRaidReconfig = $true
        }
    }

    # Configure storage
    $bootDisk = $allDisks | Where-Object { $_.IsBoot -eq $true } | Select-Object -First 1
    $dataDisks = $allDisks | Where-Object { $_.IsBoot -eq $false }

    if ($bootDisk) {
        Write-ScriptLog "Boot Disk: Disk $($bootDisk.Number) - $($bootDisk.Model)" -Level "Info"

        # Check OS partition size
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

    # Configure data disks
    if ($dataDisks.Count -gt 0) {
        Write-ScriptLog "Configuring $($dataDisks.Count) data disk(s)..." -Level "Info"

        foreach ($disk in $dataDisks) {
            $diskNumber = $disk.Number
            $mediaType = Get-MediaType -Disk $disk
            $volumeLabel = "$($Config.StorageRedundancy)-$mediaType-01"

            if ($disk.PartitionStyle -eq 'RAW') {
                Write-ScriptLog "Initializing Disk $diskNumber as GPT..." -Level "Info"
                Initialize-Disk -Number $diskNumber -PartitionStyle GPT -PassThru | Out-Null

                $partition = New-Partition -DiskNumber $diskNumber -UseMaximumSize -AssignDriveLetter
                Format-Volume -DriveLetter $partition.DriveLetter `
                             -FileSystem NTFS `
                             -AllocationUnitSize 1024 `
                             -NewFileSystemLabel $volumeLabel `
                             -Confirm:$false | Out-Null

                Write-ScriptLog "Configured Disk $diskNumber as $($partition.DriveLetter): drive" -Level "Success"
            } else {
                Write-ScriptLog "Disk $diskNumber already initialized" -Level "Info"
            }
        }
    }
    #endregion

    #region Step 2: Install Hyper-V Role
    Write-ScriptLog "Step 2: Installing Hyper-V Role..." -Level "Info"

    $hyperV = Get-WindowsFeature -Name Hyper-V
    if ($hyperV.InstallState -ne "Installed") {
        Write-ScriptLog "Installing Hyper-V..." -Level "Info"
        Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -IncludeAllSubFeature -Restart:$false
        Write-ScriptLog "Hyper-V installed successfully" -Level "Success"
        $Global:RestartRequired = $true
    } else {
        Write-ScriptLog "Hyper-V already installed" -Level "Info"
    }

    # Configure Hyper-V storage paths
    $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                 Select-Object -First 1 -ExpandProperty DriveLetter

    if ($dataDrive) {
        Set-VMHost -VirtualHardDiskPath "${dataDrive}:\Hyper-V\Virtual Hard Disks"
        Set-VMHost -VirtualMachinePath "${dataDrive}:\Hyper-V"

        New-Item -Path "${dataDrive}:\Hyper-V\Virtual Hard Disks" -ItemType Directory -Force | Out-Null
        New-Item -Path "${dataDrive}:\Hyper-V\Virtual Machines" -ItemType Directory -Force | Out-Null

        Write-ScriptLog "Hyper-V configured with storage on ${dataDrive}: drive" -Level "Success"
    }
    #endregion

    #region Step 3: Configure Network Teaming
    if (-not $Config.SkipNetworkTeaming) {
        Write-ScriptLog "Step 3: Configuring Network Teaming..." -Level "Info"

        # Get network adapters
        $adapters = Get-NetAdapter | Where-Object {
            $_.Status -eq 'Up' -and
            $_.Virtual -eq $false -and
            $_.InterfaceDescription -notlike "*Virtual*" -and
            $_.InterfaceDescription -notlike "*Hyper-V*"
        }

        if ($adapters.Count -ge 2) {
            Write-ScriptLog "Found $($adapters.Count) network adapters for teaming" -Level "Info"

            if ($Config.AutoNICTeaming -or $Config.NonInteractive) {
                # Auto-configure teams
                Write-ScriptLog "Auto-configuring network teams..." -Level "Info"

                $nicDetails = Get-NICDetails
                $nicsByBus = $nicDetails | Where-Object { $_.Status -eq "Up" } | Group-Object PCIBus

                $teamNumber = 1
                foreach ($busGroup in $nicsByBus) {
                    if ($busGroup.Count -ge 2) {
                        $teamNics = $busGroup.Group | Select-Object -First $Config.TeamsOf
                        $nicNames = $teamNics.Name

                        Write-ScriptLog "Creating SET$teamNumber with NICs: $($nicNames -join ', ')" -Level "Info"

                        New-VMSwitch -Name "SET$teamNumber" `
                                    -NetAdapterName $nicNames `
                                    -EnableEmbeddedTeaming $true `
                                    -AllowManagementOS $true

                        Rename-VMNetworkAdapter -Name "SET$teamNumber" -NewName "vNIC-Mgmt-SET$teamNumber" -ManagementOS

                        Write-ScriptLog "Created SET$teamNumber successfully" -Level "Success"
                        $teamNumber++
                    }
                }
            } else {
                # Interactive teaming configuration
                Write-ScriptLog "Manual network team configuration required" -Level "Warning"
                Write-Host "Please configure network teams manually after setup" -ForegroundColor Yellow
            }
        } else {
            Write-ScriptLog "Insufficient network adapters for teaming (need at least 2)" -Level "Warning"
        }
    } else {
        Write-ScriptLog "Step 3: Skipping network teaming" -Level "Info"
    }
    #endregion

    #region Step 4: Install Windows Features
    Write-ScriptLog "Step 4: Installing Windows Features..." -Level "Info"

    # Install additional features
    $features = @(
        "SNMP-Service",
        "RSAT-Hyper-V-Tools",
        "Hyper-V-PowerShell",
        "Windows-Defender"
    )

    foreach ($feature in $features) {
        $feat = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
        if ($feat -and $feat.InstallState -ne "Installed") {
            Write-ScriptLog "Installing $feature..." -Level "Info"
            Install-WindowsFeature -Name $feature -IncludeManagementTools
        }
    }

    Write-ScriptLog "Windows features installation complete" -Level "Success"
    #endregion

    #region Step 5: Configure Windows Settings
    Write-ScriptLog "Step 5: Configuring Windows Settings..." -Level "Info"

    # Disable Server Manager auto-start
    Get-ScheduledTask -TaskName ServerManager -ErrorAction SilentlyContinue |
        Disable-ScheduledTask -ErrorAction SilentlyContinue

    # Set power plan to High Performance
    powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

    # Enable RDP
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

    Write-ScriptLog "Windows settings configured" -Level "Success"
    #endregion

    #region Step 6: Install Applications
    Write-ScriptLog "Step 6: Installing Applications..." -Level "Info"

    # Check for WinGet
    $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetPath) {
        $apps = @(
            @{id = "Mozilla.Firefox"; name = "Firefox"},
            @{id = "7zip.7zip"; name = "7-Zip"},
            @{id = "Notepad++.Notepad++"; name = "Notepad++"}
        )

        foreach ($app in $apps) {
            Write-ScriptLog "Installing $($app.name)..." -Level "Info"
            winget install --id $app.id --exact --silent --accept-package-agreements --accept-source-agreements
        }
    } else {
        Write-ScriptLog "WinGet not available - skipping application installation" -Level "Warning"
    }
    #endregion

    #region Step 7: Configure BitLocker (Optional)
    if (-not $Config.SkipBitLocker) {
        Write-ScriptLog "Step 7: Configuring BitLocker..." -Level "Info"

        $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
        if ($tpm) {
            # Enable BitLocker on OS drive
            $osDrive = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq "OperatingSystem" }
            if ($osDrive.ProtectionStatus -eq "Off") {
                Enable-BitLocker -MountPoint $osDrive.MountPoint -TpmProtector -EncryptionMethod AES256
                Add-BitLockerKeyProtector -MountPoint $osDrive.MountPoint -RecoveryPasswordProtector
                Write-ScriptLog "BitLocker enabled on OS drive" -Level "Success"
            }
        } else {
            Write-ScriptLog "No TPM detected - skipping BitLocker" -Level "Warning"
        }
    } else {
        Write-ScriptLog "Step 7: Skipping BitLocker configuration" -Level "Info"
    }
    #endregion

    #region Step 8: Windows Updates (Optional)
    if (-not $Config.SkipWindowsUpdate) {
        Write-ScriptLog "Step 8: Installing Windows Updates..." -Level "Info"

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
        Write-ScriptLog "Step 8: Skipping Windows Updates" -Level "Info"
    }
    #endregion

    Write-ScriptLog "========================================" -Level "Info"
    Write-ScriptLog "Hyper-V Host Setup Complete!" -Level "Success"
    Write-ScriptLog "Server Name: $NewComputerName" -Level "Success"
    Write-ScriptLog "========================================" -Level "Info"

    if ($Global:RestartRequired) {
        Write-ScriptLog "RESTART REQUIRED to complete configuration" -Level "Warning"

        if ($Config.NonInteractive) {
            Write-ScriptLog "Server will restart automatically in 60 seconds" -Level "Warning"
            shutdown /r /t 60 /c "Hyper-V Host Setup Complete - Restarting"
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