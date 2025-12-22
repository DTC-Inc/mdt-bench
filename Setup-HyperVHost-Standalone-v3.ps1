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
    Version: 3.2 MSP Template (Enhanced Logging & Timeout Handling)
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
## $TimeZone = "Eastern Standard Time"  # Time zone to set (e.g., "Pacific Standard Time", "Central Standard Time", "Mountain Standard Time")

#Requires -RunAsAdministrator
#Requires -Version 5.1

# ============================================================================
# SECTION 1: RMM VARIABLE DECLARATION AND INPUT HANDLING
# ============================================================================

$ScriptVersion = "3.2"
$ScriptLogName = "HyperVHost-Setup-v3"
$ServerRole = "HV"  # Hyper-V Host role code

# Helper function to convert strings to booleans
function ConvertTo-Boolean {
    param([object]$Value)

    # Already a boolean - return as-is
    if ($Value -is [bool]) { return $Value }

    # Convert string to boolean
    if ($Value -is [string]) {
        switch ($Value.ToLower().Trim()) {
            "true"  { return $true }
            "1"     { return $true }
            "yes"   { return $true }
            "false" { return $false }
            "0"     { return $false }
            "no"    { return $false }
            default { return $false }  # Default to false for safety
        }
    }

    # Numeric conversion
    if ($Value -is [int] -or $Value -is [long]) {
        return [bool]$Value
    }

    # Default to false
    return $false
}

# Default configuration values
if ($null -eq $CompanyName) { $CompanyName = "DTC" }
if ($null -eq $SkipWindowsUpdate) { $SkipWindowsUpdate = $false }
if ($null -eq $SkipBitLocker) { $SkipBitLocker = $false }
if ($null -eq $SkipNetworkTeaming) { $SkipNetworkTeaming = $false }
if ($null -eq $TeamsOf) { $TeamsOf = 2 }
if ($null -eq $AutoNICTeaming) { $AutoNICTeaming = $false }
if ($null -eq $StorageRedundancy) { $StorageRedundancy = "ers" }
if ($null -eq $AcceptRAIDWarning) { $AcceptRAIDWarning = $false }
if ($null -eq $TimeZone) { $TimeZone = "Eastern Standard Time" }

# Convert string values to proper booleans (in case RMM passes strings)
$SkipWindowsUpdate = ConvertTo-Boolean $SkipWindowsUpdate
$SkipBitLocker = ConvertTo-Boolean $SkipBitLocker
$SkipNetworkTeaming = ConvertTo-Boolean $SkipNetworkTeaming
$AutoNICTeaming = ConvertTo-Boolean $AutoNICTeaming
$AcceptRAIDWarning = ConvertTo-Boolean $AcceptRAIDWarning

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

    $input = Read-Host "Enter time zone (default: Eastern Standard Time, type 'list' to see all)"
    if ($input -eq 'list') {
        Write-Host "Common US Time Zones:" -ForegroundColor Yellow
        Write-Host "  Eastern Standard Time" -ForegroundColor Gray
        Write-Host "  Central Standard Time" -ForegroundColor Gray
        Write-Host "  Mountain Standard Time" -ForegroundColor Gray
        Write-Host "  Pacific Standard Time" -ForegroundColor Gray
        Write-Host "  Alaskan Standard Time" -ForegroundColor Gray
        Write-Host "  Hawaiian Standard Time" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Use 'Get-TimeZone -ListAvailable' in PowerShell to see all available time zones" -ForegroundColor Gray
        $input = Read-Host "Enter time zone"
    }
    if (![string]::IsNullOrEmpty($input)) {
        $TimeZone = $input
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
$Global:ProgressStep = 0
$Global:TotalSteps = 10

function Write-LogProgress {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logMessage = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "Error"   { Write-Host $logMessage -ForegroundColor Red }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Debug"   { Write-Host $logMessage -ForegroundColor Gray }
        default   { Write-Host $logMessage }
    }

    # Force flush the transcript buffer
    if ($Host.Name -eq "Windows PowerShell ISE Host" -or $Host.Name -eq "ConsoleHost") {
        [System.Console]::Out.Flush()
    }
}

function Start-ProgressStep {
    param([string]$StepName)

    $Global:ProgressStep++
    $percentComplete = [math]::Round(($Global:ProgressStep / $Global:TotalSteps) * 100)
    Write-LogProgress "===== STEP $($Global:ProgressStep)/$($Global:TotalSteps) ($percentComplete%): $StepName =====" "Info"
}

function Add-RebootReason {
    param([string]$Reason)
    $Global:RebootReasons += $Reason
    $Global:RestartRequired = $true
    Write-LogProgress "Reboot Required: $Reason" "Warning"
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

    Write-LogProgress "Enumerating network adapters..." "Debug"
    try {
        $adapters = Get-NetAdapter -ErrorAction Stop | Where-Object {
            $_.Virtual -eq $false -and
            $_.InterfaceDescription -notlike "*Virtual*" -and
            $_.InterfaceDescription -notlike "*Hyper-V*" -and
            $_.DriverFileName -notlike "usb*"
        }
        Write-LogProgress "Found $($adapters.Count) physical network adapters" "Debug"
    } catch {
        Write-LogProgress "Error enumerating network adapters: $_" "Warning"
        return $nicInfo
    }

    foreach ($adapter in $adapters) {
        $pnpDevice = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -eq $adapter.InterfaceDescription }

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
    Write-LogProgress "========================================" "Success"
    Write-LogProgress "Starting $ScriptLogName v$ScriptVersion" "Success"
    Write-LogProgress "========================================" "Success"
    Write-LogProgress "Script Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "Info"
    Write-LogProgress "PowerShell Version: $($PSVersionTable.PSVersion)" "Debug"
    Write-LogProgress "OS Version: $([System.Environment]::OSVersion.VersionString)" "Debug"
    Write-LogProgress "Description: $Description" "Info"
    Write-LogProgress "Log Path: $LogFile" "Info"
    Write-LogProgress "RMM Mode: $(if ($RMM -eq 1) { 'Yes' } else { 'No' })" "Info"
    Write-LogProgress "Company Name: $CompanyName" "Info"
    Write-LogProgress "Server Sequence: $ServerSequence" "Info"
    Write-LogProgress "New Computer Name: $NewComputerName" "Info"
    Write-LogProgress "Current Computer Name: $env:COMPUTERNAME" "Info"
    Write-LogProgress "" "Info"
    Write-LogProgress "Configuration Options:" "Info"
    Write-LogProgress "  Skip Windows Update: $SkipWindowsUpdate" "Info"
    Write-LogProgress "  Skip BitLocker: $SkipBitLocker" "Info"
    Write-LogProgress "  Skip Network Teaming: $SkipNetworkTeaming" "Info"
    Write-LogProgress "  NICs per Team: $TeamsOf" "Info"
    Write-LogProgress "  Auto NIC Teaming: $AutoNICTeaming" "Info"
    Write-LogProgress "  Storage Redundancy: $StorageRedundancy" "Info"
    Write-LogProgress "  Time Zone: $TimeZone" "Info"
    Write-LogProgress "" "Info"

    # ============================================================================
    # PHASE 1: INSTALL EVERYTHING THAT REQUIRES REBOOTS
    # ============================================================================

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "PHASE 1: Installing Components That Require Reboots" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    #region Step 1: Rename Computer (Requires Reboot)
    Start-ProgressStep "Computer Naming Configuration"

    if ($env:COMPUTERNAME -ne $NewComputerName) {
        Write-LogProgress "Renaming computer from '$env:COMPUTERNAME' to '$NewComputerName'..." "Info"

        try {
            Rename-Computer -NewName $NewComputerName -Force -ErrorAction Stop
            Write-LogProgress "Computer renamed successfully to '$NewComputerName'" "Success"
            Add-RebootReason "Computer rename to $NewComputerName"
        } catch {
            Write-LogProgress "Failed to rename computer: $_" "Error"
            if ($RMM -ne 1) {
                $continue = Read-Host "Failed to rename computer. Continue anyway? (y/n)"
                if ($continue -ne 'y') {
                    throw "Setup cancelled due to computer rename failure"
                }
            }
        }
    } else {
        Write-LogProgress "Computer name already set to '$NewComputerName'" "Success"
    }
    #endregion

    #region Step 2: Install ALL Windows Features and Roles (Many Require Reboots)
    Start-ProgressStep "Windows Features and Roles Installation"
    Write-LogProgress "This includes Hyper-V and related components that require reboots" "Warning"

    # Core Hyper-V installation
    Write-LogProgress "Checking Hyper-V feature status (this may take 10-30 seconds)..." "Info"
    try {
        $hyperV = Get-WindowsFeature -Name Hyper-V
        Write-LogProgress "Get-WindowsFeature completed. Install state: $($hyperV.InstallState)" "Debug"
    } catch {
        Write-LogProgress "Failed to check Hyper-V feature: $_" "Error"
        throw "Cannot check Windows Features - Component Store may be corrupted"
    }

    if ($hyperV.InstallState -ne "Installed") {
        Write-LogProgress "Installing Hyper-V Role (REQUIRES REBOOT)..." "Info"
        $result = Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -IncludeAllSubFeature -Restart:$false
        if ($result.RestartNeeded -eq "Yes") {
            Add-RebootReason "Hyper-V Role Installation"
        }
        Write-LogProgress "Hyper-V installed successfully" "Success"
    } else {
        Write-LogProgress "Hyper-V already installed" "Success"
    }

    # Install ALL other features we need upfront
    Write-Host "Installing additional Windows features..."

    $featuresToInstall = @(
        @{Name = "RSAT-Hyper-V-Tools"; Description = "Hyper-V Management Tools"},
        @{Name = "Hyper-V-PowerShell"; Description = "Hyper-V PowerShell Module"},
        @{Name = "Windows-Defender"; Description = "Windows Defender"},
        @{Name = "Multipath-IO"; Description = "MPIO for Storage"},
        @{Name = "BitLocker"; Description = "BitLocker Drive Encryption"},
        @{Name = "RSAT-Feature-Tools-BitLocker"; Description = "BitLocker Administration Utilities"}
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
    Start-ProgressStep "OEM Management Tools Installation"

    Write-LogProgress "Detecting hardware manufacturer (querying WMI)..." "Info"
    try {
        $Manufacturer = Get-CimInstance -ClassName Win32_ComputerSystem -OperationTimeoutSec 30 | Select-Object -ExpandProperty Manufacturer
        Write-LogProgress "Hardware manufacturer detected: $Manufacturer" "Debug"
    } catch {
        Write-LogProgress "Failed to detect manufacturer via CIM, trying WMI..." "Warning"
        try {
            $Manufacturer = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).Manufacturer
            Write-LogProgress "Hardware manufacturer detected via WMI: $Manufacturer" "Debug"
        } catch {
            Write-LogProgress "Cannot detect hardware manufacturer: $_" "Error"
            $Manufacturer = "Unknown"
        }
    }

    if ($Manufacturer -like "Dell*") {
        Write-LogProgress "Dell hardware detected - installing Dell OpenManage and tools" "Info"

        # Check if already installed
        $omsaInstalled = Test-Path "C:\Program Files\Dell\SysMgt\oma\bin"

        if (!$omsaInstalled) {
            Write-Host "Dell OpenManage not found, installing..."

            # Ensure BITS service is running for reliable downloads
            Write-LogProgress "Ensuring BITS service is running..." "Debug"
            Start-Service -Name BITS -ErrorAction SilentlyContinue

            # Download URLs for Dell tools - Using Backblaze B2 public bucket
            $downloads = @(
                @{
                    Name = "OpenManage Server Administrator"
                    Urls = @(
                        "https://public-dtc.s3.us-west-002.backblazeb2.com/repo/vendors/dell/OM-SrvAdmin-Dell-Web-WINX64-11.0.1.0-5494_A00.exe"
                    )
                    File = "$env:WINDIR\temp\OMSA_Setup.exe"
                    IsExtractor = $true  # This exe extracts to C:\OpenManage
                    ExtractPath = "C:\OpenManage"
                    ActualSetup = "C:\OpenManage\windows\setup.exe"
                    Args = "/qn"  # Completely silent installation
                    ShowWindow = $false
                },
                @{
                    Name = "iDRAC Service Module (iSM)"
                    Urls = @(
                        "https://public-dtc.s3.us-west-002.backblazeb2.com/repo/vendors/dell/OM-iSM-Dell-Web-X64-5.4.2.0-4048.exe"
                    )
                    File = "$env:WINDIR\temp\iSM_Setup.exe"
                    IsExtractor = $true  # This exe extracts to C:\OpenManage\iSM
                    ExtractPath = "C:\OpenManage\iSM"
                    ActualSetup = "C:\OpenManage\iSM\windows\idracsvcmod.msi"
                    Args = "/qn"  # Completely silent MSI installation
                    ShowWindow = $false
                },
                @{
                    Name = "Dell System Update"
                    Urls = @(
                        "https://public-dtc.s3.us-west-002.backblazeb2.com/repo/vendors/dell/Systems-Management_Application_W7K0J_WN64_2.1.2.0_A01.EXE"
                    )
                    File = "$env:WINDIR\temp\DSU_Setup.exe"
                    Args = "/s"  # Silent installation
                    ShowWindow = $false
                }
            )

            foreach ($download in $downloads) {
                $downloadSuccess = $false

                # Try each URL in order until one succeeds
                foreach ($url in $download.Urls) {
                    try {
                        Write-LogProgress "  Downloading $($download.Name)..." "Info"
                        Write-LogProgress "    Trying: $url" "Debug"

                        # Try BITS transfer first for better reliability
                        try {
                            $bitsJob = Start-BitsTransfer -Source $url -Destination $download.File `
                                -DisplayName $download.Name -Priority Normal -Asynchronous -ErrorAction Stop

                            Write-LogProgress "    BITS transfer started (Job ID: $($bitsJob.JobId))" "Debug"

                            # Monitor BITS job progress
                            while (($bitsJob.JobState -eq "Transferring") -or ($bitsJob.JobState -eq "Connecting")) {
                                $percentComplete = if ($bitsJob.BytesTotal -gt 0) {
                                    [math]::Round(($bitsJob.BytesTransferred / $bitsJob.BytesTotal) * 100, 2)
                                } else { 0 }
                                Write-LogProgress "    Progress: $percentComplete% - $($bitsJob.JobState)" "Debug"
                                Start-Sleep -Seconds 5
                                $bitsJob = Get-BitsTransfer -JobId $bitsJob.JobId
                            }

                            if ($bitsJob.JobState -eq "Transferred") {
                                Complete-BitsTransfer -BitsJob $bitsJob
                                Write-LogProgress "    BITS download successful" "Success"
                                $downloadSuccess = $true
                                break
                            } else {
                                Write-LogProgress "    BITS transfer failed: $($bitsJob.JobState)" "Warning"
                                Remove-BitsTransfer -BitsJob $bitsJob -ErrorAction SilentlyContinue
                                throw "BITS transfer failed"
                            }
                        } catch {
                            Write-LogProgress "    BITS failed: $_" "Warning"
                            Write-LogProgress "    Falling back to direct download..." "Info"

                            # Fallback to Invoke-WebRequest
                            $progressPreference = 'SilentlyContinue'  # Speed up download
                            Invoke-WebRequest -Uri $url -OutFile $download.File -UseBasicParsing -ErrorAction Stop
                            $progressPreference = 'Continue'

                            Write-LogProgress "    Direct download successful" "Success"
                            $downloadSuccess = $true
                            break
                        }
                    } catch {
                        Write-LogProgress "    Failed: $_" "Warning"
                        continue
                    }
                }

                if ($downloadSuccess) {
                    try {
                        # Check if this is an extractor (like OpenManage)
                        if ($download.IsExtractor) {
                            Write-LogProgress "  Extracting $($download.Name)..." "Info"
                            Write-LogProgress "    Running extractor to $($download.ExtractPath)..." "Debug"

                            # Run extractor silently - no window needed for extraction
                            $extractProcess = Start-Process -FilePath $download.File -ArgumentList "/s" -PassThru -NoNewWindow -ErrorAction Stop

                            # Wait for extraction to complete
                            $extractStartTime = Get-Date
                            while (!$extractProcess.HasExited) {
                                $elapsed = [math]::Round(((Get-Date) - $extractStartTime).TotalMinutes, 1)
                                if ($elapsed -gt 0 -and ($elapsed % 1) -eq 0) {
                                    Write-LogProgress "    Still extracting... ($elapsed minutes elapsed)" "Debug"
                                }
                                Start-Sleep -Seconds 10
                            }

                            $extractTime = [math]::Round(((Get-Date) - $extractStartTime).TotalMinutes, 1)
                            Write-LogProgress "    Extraction completed (took $extractTime minutes)" "Success"

                            # Verify extracted setup exists
                            if (!(Test-Path $download.ActualSetup)) {
                                throw "Extracted setup not found at: $($download.ActualSetup)"
                            }

                            Write-LogProgress "  Installing $($download.Name) from extracted files..." "Info"

                            # Now run the actual setup from extracted location
                            if ($download.ShowWindow) {
                                Write-LogProgress "    Installation window will show progress - DO NOT CLOSE IT!" "Warning"
                                $process = Start-Process -FilePath $download.ActualSetup -ArgumentList $download.Args -PassThru
                            } else {
                                $process = Start-Process -FilePath $download.ActualSetup -ArgumentList $download.Args -PassThru -NoNewWindow
                            }
                        } else {
                            # Normal installer - not an extractor
                            Write-LogProgress "  Installing $($download.Name)..." "Info"

                            # Start installer - show window if configured
                            if ($download.ShowWindow) {
                                Write-LogProgress "    Installation window will show progress - DO NOT CLOSE IT!" "Warning"
                                $process = Start-Process -FilePath $download.File -ArgumentList $download.Args -PassThru
                            } else {
                                $process = Start-Process -FilePath $download.File -ArgumentList $download.Args -PassThru -NoNewWindow
                            }
                        }

                        # Wait for installation to complete - no arbitrary timeout
                        Write-LogProgress "    Waiting for installation to complete..." "Info"
                        $startTime = Get-Date

                        while (!$process.HasExited) {
                            $elapsed = [math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)

                            # Report progress every minute
                            if ($elapsed -gt 0 -and ($elapsed % 1) -eq 0) {
                                Write-LogProgress "    Still installing... ($elapsed minutes elapsed)" "Debug"
                            }

                            Start-Sleep -Seconds 10
                        }

                        # Check exit code
                        $totalTime = [math]::Round(((Get-Date) - $startTime).TotalMinutes, 1)

                        if ($process.ExitCode -eq 0) {
                            Write-LogProgress "  $($download.Name) installed successfully (took $totalTime minutes)" "Success"
                        } elseif ($process.ExitCode -eq 3010 -or $process.ExitCode -eq 3011) {
                            Write-LogProgress "  $($download.Name) installed but requires reboot (exit code: $($process.ExitCode))" "Warning"
                            Add-RebootReason "$($download.Name) installation"
                        } else {
                            Write-LogProgress "  $($download.Name) installer returned exit code: $($process.ExitCode)" "Warning"
                        }
                    } catch {
                        Write-Host "  Failed to install $($download.Name): $_" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "  Failed to download $($download.Name) from all sources" -ForegroundColor Red
                }
            }

            # Dell tools may require reboot
            Add-RebootReason "Dell OpenManage and Tools Installation"
            Write-Host "Dell tools installed (MAY REQUIRE REBOOT)" -ForegroundColor Yellow

            # Run Dell System Update to apply firmware/driver updates
            $dsuPath = "C:\Program Files\Dell\SysMgt\DSU\dsu.exe"
            if (Test-Path $dsuPath) {
                Write-Host ""
                Write-Host "========================================" -ForegroundColor Cyan
                Write-Host "Running Dell System Update..." -ForegroundColor Cyan
                Write-Host "========================================" -ForegroundColor Cyan
                Write-LogProgress "Dell System Update found at: $dsuPath" "Info"
                Write-LogProgress "Scanning for firmware and driver updates..." "Info"

                try {
                    # Run DSU to apply all available updates
                    # --apply-upgrades: Apply all available updates
                    # --non-interactive: Run without user prompts
                    Write-Host "  This may take 10-30 minutes depending on available updates..." -ForegroundColor Yellow

                    $dsuStartTime = Get-Date
                    $dsuProcess = Start-Process -FilePath $dsuPath `
                                                -ArgumentList "--apply-upgrades --non-interactive" `
                                                -PassThru -NoNewWindow -Wait

                    $dsuTotalTime = [math]::Round(((Get-Date) - $dsuStartTime).TotalMinutes, 1)

                    # DSU exit codes:
                    # 0 = Success, no updates needed or all updates applied successfully
                    # 1 = Updates applied successfully, but reboot required
                    # 2 = Updates available but not applied (errors occurred)
                    # 3 = No updates available

                    switch ($dsuProcess.ExitCode) {
                        0 {
                            Write-Host "  Dell System Update completed successfully (took $dsuTotalTime minutes)" -ForegroundColor Green
                            Write-LogProgress "  DSU: No updates needed or all updates applied" "Success"
                        }
                        1 {
                            Write-Host "  Dell System Update completed - REBOOT REQUIRED (took $dsuTotalTime minutes)" -ForegroundColor Yellow
                            Write-LogProgress "  DSU: Updates applied, reboot required" "Warning"
                            Add-RebootReason "Dell System Update firmware/driver updates"
                        }
                        3 {
                            Write-Host "  Dell System Update: No updates available (took $dsuTotalTime minutes)" -ForegroundColor Green
                            Write-LogProgress "  DSU: System is up to date" "Success"
                        }
                        default {
                            Write-Host "  Dell System Update completed with exit code: $($dsuProcess.ExitCode)" -ForegroundColor Yellow
                            Write-LogProgress "  DSU: Exit code $($dsuProcess.ExitCode) - check logs for details" "Warning"
                        }
                    }
                } catch {
                    Write-Host "  Failed to run Dell System Update: $_" -ForegroundColor Yellow
                    Write-LogProgress "  DSU execution error: $_" "Warning"
                }
                Write-Host ""
            } else {
                Write-LogProgress "Dell System Update not found - skipping firmware updates" "Warning"
            }
        } else {
            Write-Host "Dell OpenManage already installed" -ForegroundColor Green

            # If OpenManage is already installed, still offer to run DSU
            $dsuPath = "C:\Program Files\Dell\SysMgt\DSU\dsu.exe"
            if (Test-Path $dsuPath) {
                Write-Host ""
                Write-Host "Running Dell System Update to check for firmware/driver updates..." -ForegroundColor Cyan
                Write-LogProgress "Dell System Update found at: $dsuPath" "Info"

                try {
                    $dsuStartTime = Get-Date
                    $dsuProcess = Start-Process -FilePath $dsuPath `
                                                -ArgumentList "--apply-upgrades --non-interactive" `
                                                -PassThru -NoNewWindow -Wait

                    $dsuTotalTime = [math]::Round(((Get-Date) - $dsuStartTime).TotalMinutes, 1)

                    switch ($dsuProcess.ExitCode) {
                        0 {
                            Write-Host "  Dell System Update completed successfully (took $dsuTotalTime minutes)" -ForegroundColor Green
                            Write-LogProgress "  DSU: No updates needed or all updates applied" "Success"
                        }
                        1 {
                            Write-Host "  Dell System Update completed - REBOOT REQUIRED (took $dsuTotalTime minutes)" -ForegroundColor Yellow
                            Write-LogProgress "  DSU: Updates applied, reboot required" "Warning"
                            Add-RebootReason "Dell System Update firmware/driver updates"
                        }
                        3 {
                            Write-Host "  Dell System Update: No updates available (took $dsuTotalTime minutes)" -ForegroundColor Green
                            Write-LogProgress "  DSU: System is up to date" "Success"
                        }
                        default {
                            Write-Host "  Dell System Update completed with exit code: $($dsuProcess.ExitCode)" -ForegroundColor Yellow
                            Write-LogProgress "  DSU: Exit code $($dsuProcess.ExitCode) - check logs for details" "Warning"
                        }
                    }
                } catch {
                    Write-Host "  Failed to run Dell System Update: $_" -ForegroundColor Yellow
                    Write-LogProgress "  DSU execution error: $_" "Warning"
                }
            }
        }
    } else {
        Write-Host "Non-Dell hardware - skipping OEM tools"
    }
    #endregion

    #region Step 4: Windows Updates (Requires Reboot)
    if (!$SkipWindowsUpdate) {
        Start-ProgressStep "Windows Updates Installation"
        Write-LogProgress "This typically requires a reboot" "Warning"

        try {
            # Ensure NuGet and PSWindowsUpdate are installed
            Write-LogProgress "Checking for NuGet package provider..." "Info"
            if (!(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Write-LogProgress "Installing NuGet provider (this may hang for 30-60 seconds on first run)..." "Info"
                Install-PackageProvider -Name NuGet -Force -Confirm:$false | Out-Null
                Write-LogProgress "NuGet provider installed" "Success"
            }

            Write-LogProgress "Checking for PSWindowsUpdate module..." "Info"
            if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
                Write-LogProgress "Installing PSWindowsUpdate module (may take 1-2 minutes)..." "Info"
                Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
                Install-Module PSWindowsUpdate -Force -Confirm:$false | Out-Null
                Write-LogProgress "PSWindowsUpdate module installed" "Success"
            }

            Write-LogProgress "Importing PSWindowsUpdate module..." "Info"
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
    Start-ProgressStep "Storage Configuration"

    # Get all disks and analyze
    Write-LogProgress "Enumerating storage disks..." "Info"
    $allDisks = Get-Disk -ErrorAction SilentlyContinue | Sort-Object Number
    Write-LogProgress "Found $($allDisks.Count) disk(s)" "Info"

    # Get all volumes to check for existing configuration
    $allVolumes = Get-Volume | Where-Object { $_.DriveLetter -ne $null }
    $osVolume = $allVolumes | Where-Object { $_.DriveLetter -eq 'C' }
    $dataVolumes = $allVolumes | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveType -eq 'Fixed' }

    # Check for RAID configuration issues
    $raidDisks = $allDisks | Where-Object { $_.Model -match "PERC|RAID|Virtual|BOSS|MegaRAID" }

    # Critical check: Are OS and Data volumes on the same physical/RAID disk?
    if ($osVolume -and $dataVolumes.Count -gt 0) {
        # Get the disk number for the OS
        $osPartition = Get-Partition -DriveLetter 'C'
        $osDiskNumber = $osPartition.DiskNumber

        # Check if any data volumes are on the same disk as OS
        $dataOnSameDisk = @()
        foreach ($dataVol in $dataVolumes) {
            try {
                $dataPartition = Get-Partition -DriveLetter $dataVol.DriveLetter -ErrorAction SilentlyContinue
                if ($dataPartition -and $dataPartition.DiskNumber -eq $osDiskNumber) {
                    $dataOnSameDisk += $dataVol.DriveLetter
                }
            } catch {
                # Ignore errors for volumes without partitions
            }
        }

        if ($dataOnSameDisk.Count -gt 0) {
            $diskInfo = Get-Disk -Number $osDiskNumber

            # Check if this is a RAID disk
            if ($diskInfo.Model -match "PERC|RAID|Virtual|BOSS|MegaRAID") {
                Write-Host "" -ForegroundColor Red
                Write-Host "========================================" -ForegroundColor Red
                Write-Host "CRITICAL: RAID CONFIGURATION ERROR!" -ForegroundColor Red
                Write-Host "========================================" -ForegroundColor Red
                Write-Host ""
                Write-Host "OS (C:) and Data volumes ($($dataOnSameDisk -join ', '):) are on the SAME RAID virtual disk!" -ForegroundColor Red
                Write-Host "Disk: $($diskInfo.Model) - Size: $([math]::Round($diskInfo.Size/1GB,2)) GB" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "This configuration is NOT SUPPORTED for production servers!" -ForegroundColor Red
                Write-Host "Reasons:" -ForegroundColor Yellow
                Write-Host "  - Poor I/O performance (OS and Data compete for same RAID resources)" -ForegroundColor Yellow
                Write-Host "  - Cannot optimize RAID levels separately (OS needs RAID1, Data needs RAID5/6/10)" -ForegroundColor Yellow
                Write-Host "  - Difficult to expand storage independently" -ForegroundColor Yellow
                Write-Host "  - Backup/restore complexity" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "REQUIRED RAID RECONFIGURATION:" -ForegroundColor Cyan
                Write-Host "========================================" -ForegroundColor Cyan

                if ($Manufacturer -like "Dell*") {
                    Write-Host "Dell PERC Controller Instructions:" -ForegroundColor Green
                    Write-Host "1. Reboot server and press Ctrl+R to enter RAID configuration" -ForegroundColor White
                    Write-Host "2. Delete the current virtual disk (WARNING: This will destroy all data!)" -ForegroundColor White
                    Write-Host "3. Create TWO separate virtual disks from the same RAID group:" -ForegroundColor White
                    Write-Host ""
                    Write-Host "   Virtual Disk 1 (OS):" -ForegroundColor Cyan
                    Write-Host "   - Name: OS_VD" -ForegroundColor White
                    Write-Host "   - Size: 300-500 GB" -ForegroundColor White
                    Write-Host "   - RAID Level: RAID 1 (using first 2 disks)" -ForegroundColor White
                    Write-Host "   - Strip Size: 64K" -ForegroundColor White
                    Write-Host "   - Read Policy: Read Ahead" -ForegroundColor White
                    Write-Host "   - Write Policy: Write Back" -ForegroundColor White
                    Write-Host ""
                    Write-Host "   Virtual Disk 2 (Data):" -ForegroundColor Cyan
                    Write-Host "   - Name: DATA_VD" -ForegroundColor White
                    Write-Host "   - Size: Use remaining space" -ForegroundColor White
                    Write-Host "   - RAID Level: RAID 5/6/10 (using remaining disks)" -ForegroundColor White
                    Write-Host "   - Strip Size: 256K or 1024K" -ForegroundColor White
                    Write-Host "   - Read Policy: Read Ahead" -ForegroundColor White
                    Write-Host "   - Write Policy: Write Back" -ForegroundColor White
                    Write-Host ""
                    Write-Host "4. Initialize both virtual disks" -ForegroundColor White
                    Write-Host "5. Save configuration and reboot" -ForegroundColor White
                    Write-Host "6. Reinstall Windows Server on Virtual Disk 1" -ForegroundColor White
                    Write-Host "7. Re-run this script after OS installation" -ForegroundColor White
                } else {
                    Write-Host "Generic RAID Controller Instructions:" -ForegroundColor Green
                    Write-Host "1. Enter RAID configuration utility during boot" -ForegroundColor White
                    Write-Host "2. Delete current configuration (WARNING: This will destroy all data!)" -ForegroundColor White
                    Write-Host "3. Create separate virtual disks:" -ForegroundColor White
                    Write-Host "   - VD1: 300-500GB for OS (RAID 1 recommended)" -ForegroundColor White
                    Write-Host "   - VD2: Remaining space for Data (RAID 5/6/10)" -ForegroundColor White
                    Write-Host "4. Reinstall Windows Server on VD1" -ForegroundColor White
                    Write-Host "5. Re-run this script after OS installation" -ForegroundColor White
                }

                Write-Host ""
                Write-Host "========================================" -ForegroundColor Red

                if ($RMM -eq 1) {
                    Write-Host "EXITING: RAID reconfiguration required!" -ForegroundColor Red
                    Write-Host "This cannot be fixed remotely via RMM." -ForegroundColor Red
                    Write-Host "Physical access or IPMI/iDRAC is required to reconfigure RAID." -ForegroundColor Red
                    exit 1
                } else {
                    Write-Host "Do you want to continue anyway? (NOT RECOMMENDED)" -ForegroundColor Yellow
                    $response = Read-Host "Type 'ACCEPT RISK' to continue with this configuration"
                    if ($response -ne 'ACCEPT RISK') {
                        Write-Host "Exiting. Please reconfigure RAID as instructed above." -ForegroundColor Red
                        exit 1
                    }
                    Write-Host "WARNING: Continuing with suboptimal RAID configuration at your own risk!" -ForegroundColor Red
                }
            } else {
                # Non-RAID disk with OS and Data - still not ideal but less critical
                Write-Host "WARNING: OS and Data volumes are on the same physical disk" -ForegroundColor Yellow
                Write-Host "Disk: $($diskInfo.Model)" -ForegroundColor Yellow
                Write-Host "This is not recommended for performance reasons" -ForegroundColor Yellow

                if ($RMM -ne 1) {
                    $response = Read-Host "Continue with single disk configuration? (y/n)"
                    if ($response -ne 'y') {
                        exit 1
                    }
                }
            }
        }
    }

    # Original single RAID disk check (for fresh installs)
    if ($raidDisks.Count -eq 1 -and $dataVolumes.Count -eq 0) {
        $raidDisk = $raidDisks[0]
        $partitions = Get-Partition -DiskNumber $raidDisk.Number -ErrorAction SilentlyContinue

        # Check if we're about to create data volumes on the same RAID disk as OS
        if ($partitions | Where-Object { $_.DriveLetter -eq 'C' }) {
            Write-Host ""
            Write-Host "WARNING: Single RAID Virtual Disk Configuration Detected!" -ForegroundColor Yellow
            Write-Host "OS is on a RAID disk, and no separate data disks are available" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Recommended: Create separate RAID virtual disks (see instructions above)" -ForegroundColor Cyan
            Write-Host ""

            if ($RMM -eq 1) {
                if (!$AcceptRAIDWarning) {
                    Write-Host "ERROR: Single RAID disk detected and AcceptRAIDWarning not set!" -ForegroundColor Red
                    Write-Host "Set `$AcceptRAIDWarning=`$true in RMM to continue with this configuration" -ForegroundColor Red
                    throw "RAID reconfiguration recommended. Set AcceptRAIDWarning=true to continue."
                }
                Write-Host "Continuing with single RAID disk (AcceptRAIDWarning=true)" -ForegroundColor Yellow
            } else {
                $response = Read-Host "Continue without separate RAID virtual disks? (y/n)"
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

        # Cap OS partition at 127 GB max
        try {
            $maxOSSize = 127GB
            $currentSize = (Get-Partition -DriveLetter C).Size
            $currentSizeGB = [math]::Round($currentSize / 1GB, 2)

            Write-LogProgress "C: drive current size: $currentSizeGB GB" "Info"

            if ($currentSize -lt $maxOSSize) {
                # C: is smaller than 127 GB, expand it to 127 GB (or max available if less)
                $supportedSize = Get-PartitionSupportedSize -DriveLetter C
                $targetSize = [math]::Min($maxOSSize, $supportedSize.SizeMax)
                $targetSizeGB = [math]::Round($targetSize / 1GB, 2)

                Write-Host "Expanding C: drive to $targetSizeGB GB..."
                Resize-Partition -DriveLetter C -Size $targetSize
                Write-Host "OS partition expanded to $targetSizeGB GB" -ForegroundColor Green
            } elseif ($currentSize -gt $maxOSSize) {
                # C: is larger than 127 GB - cannot shrink automatically
                Write-Host "C: drive is $currentSizeGB GB (larger than 127 GB maximum)" -ForegroundColor Yellow
                Write-Host "Cannot automatically shrink partition - manual intervention required" -ForegroundColor Yellow
            } else {
                Write-Host "C: drive is already at target size (127 GB)" -ForegroundColor Green
            }

            # Check if data volumes already exist on boot disk
            $bootDiskPartitions = Get-Partition -DiskNumber $bootDisk.Number -ErrorAction SilentlyContinue
            $existingDataVolumesOnBootDisk = $bootDiskPartitions | Where-Object {
                $_.DriveLetter -and $_.DriveLetter -ne 'C' -and $_.Type -eq 'Basic'
            }

            if ($existingDataVolumesOnBootDisk) {
                # Data volumes already exist on boot disk - don't recreate
                foreach ($partition in $existingDataVolumesOnBootDisk) {
                    $volume = Get-Volume -DriveLetter $partition.DriveLetter -ErrorAction SilentlyContinue
                    if ($volume) {
                        Write-Host "Data volume already exists: $($partition.DriveLetter): - $($volume.FileSystemLabel) ($([math]::Round($volume.Size/1GB,2)) GB)" -ForegroundColor Green
                    }
                }
                Write-LogProgress "Skipping data volume creation - volumes already exist on boot disk" "Info"
            } else {
                # No existing data volumes - check for unallocated space
                $partitions = Get-Partition -DiskNumber $bootDisk.Number | Where-Object { $_.Type -ne 'Reserved' -and $_.Type -ne 'System' }
                $usedSpace = ($partitions | Measure-Object -Property Size -Sum).Sum
                $diskSize = $bootDisk.Size
                $unallocatedSpace = $diskSize - $usedSpace

                if ($unallocatedSpace -gt 10GB) {
                    $unallocatedGB = [math]::Round($unallocatedSpace / 1GB, 2)
                    Write-Host "Found $unallocatedGB GB of unallocated space on boot disk" -ForegroundColor Cyan
                    Write-Host "Creating data volume from unallocated space..." -ForegroundColor Cyan

                    try {
                        # Get next available drive letter (start from D:)
                        $usedLetters = Get-Partition | Where-Object { $_.DriveLetter } | Select-Object -ExpandProperty DriveLetter
                        $availableLetters = @('D', 'E', 'F', 'G', 'H') | Where-Object { $_ -notin $usedLetters }
                        $driveLetter = $availableLetters[0]

                        # Create partition from unallocated space
                        $mediaType = Get-MediaType -Disk $bootDisk
                        $volumeLabel = "$StorageRedundancy-$mediaType-01"

                        Write-LogProgress "Creating partition with drive letter $driveLetter..." "Info"
                        $newPartition = New-Partition -DiskNumber $bootDisk.Number -UseMaximumSize -DriveLetter $driveLetter

                        Write-LogProgress "Formatting volume as NTFS..." "Info"
                        Format-Volume -DriveLetter $driveLetter `
                                     -FileSystem NTFS `
                                     -NewFileSystemLabel $volumeLabel `
                                     -AllocationUnitSize 65536 `
                                     -Confirm:$false | Out-Null

                        Write-Host "Created ${driveLetter}: drive ($volumeLabel) from unallocated space" -ForegroundColor Green
                    } catch {
                        Write-Host "Could not create partition from unallocated space: $_" -ForegroundColor Yellow
                    }
                } else {
                    Write-LogProgress "No significant unallocated space found on boot disk" "Info"
                }
            }
        } catch {
            Write-Host "Could not configure OS partition: $_" -ForegroundColor Yellow
        }
    }

    # Configure additional data disks (separate physical/virtual disks)
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
    Start-ProgressStep "Hyper-V Settings Configuration"

    # Configure Hyper-V storage paths
    $dataDrive = Get-Volume | Where-Object { $_.DriveLetter -ne 'C' -and $_.DriveLetter -ne $null } |
                 Select-Object -First 1 -ExpandProperty DriveLetter

    if ($dataDrive) {
        Write-Host "Configuring Hyper-V to use ${dataDrive}: drive for VM storage..."

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
        Start-ProgressStep "Network Teaming Configuration"

        # Clean up any existing virtual switches
        Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "SET*" } | Remove-VMSwitch -Force -ErrorAction SilentlyContinue

        # Get ALL physical network adapters for teaming (regardless of link state)
        $adapters = Get-NetAdapter | Where-Object {
            $_.Virtual -eq $false -and
            $_.InterfaceDescription -notlike "*Virtual*" -and
            $_.InterfaceDescription -notlike "*Hyper-V*"
        }

        Write-LogProgress "Found $($adapters.Count) physical network adapter(s) for teaming:" "Info"
        foreach ($adapter in $adapters) {
            Write-LogProgress "  - $($adapter.Name): $($adapter.InterfaceDescription) [Status: $($adapter.Status), Speed: $($adapter.LinkSpeed)]" "Debug"
        }

        if ($adapters.Count -ge 2) {
            Write-Host "Found $($adapters.Count) network adapters available for teaming"

            if ($AutoNICTeaming -or $RMM -eq 1) {
                # Auto-configure teams
                Write-Host "Auto-configuring network teams..."

                # Simple approach: Just team all available NICs in groups of $TeamsOf
                Write-LogProgress "Creating teams from $($adapters.Count) available NICs in groups of $TeamsOf..." "Info"

                $teamNumber = 1
                $adapterIndex = 0

                while ($adapterIndex + $TeamsOf -le $adapters.Count) {
                    # Get the next group of NICs
                    $teamAdapters = $adapters[$adapterIndex..($adapterIndex + $TeamsOf - 1)]
                    $nicNames = $teamAdapters.Name

                    Write-Host "Creating SET$teamNumber with NICs: $($nicNames -join ', ')"
                    Write-LogProgress "  NIC Details:" "Debug"
                    foreach ($nic in $teamAdapters) {
                        Write-LogProgress "    - $($nic.Name): $($nic.InterfaceDescription) ($($nic.LinkSpeed))" "Debug"
                    }

                    try {
                        New-VMSwitch -Name "SET$teamNumber" `
                                    -NetAdapterName $nicNames `
                                    -EnableEmbeddedTeaming $true `
                                    -AllowManagementOS $true -ErrorAction Stop

                        # Set load balancing algorithm to Dynamic for best performance
                        Set-VMSwitchTeam -Name "SET$teamNumber" -LoadBalancingAlgorithm Dynamic

                        Rename-VMNetworkAdapter -Name "SET$teamNumber" -NewName "vNIC-Mgmt-SET$teamNumber" -ManagementOS

                        Write-Host "Created SET$teamNumber successfully with Dynamic load balancing" -ForegroundColor Green
                        $teamNumber++
                        $adapterIndex += $TeamsOf
                    } catch {
                        Write-LogProgress "Failed to create SET${teamNumber}: $_" "Error"
                        Write-Host "Failed to create SET${teamNumber} - stopping team creation" -ForegroundColor Yellow
                        break
                    }
                }

                # Handle leftover NICs if any
                $remainingNICs = $adapters.Count - $adapterIndex
                if ($remainingNICs -gt 0) {
                    Write-LogProgress "$remainingNICs NIC(s) not teamed (need $TeamsOf for a team)" "Warning"
                }

                if ($teamNumber -eq 1) {
                    Write-Host "No teams created - check logs for details" -ForegroundColor Yellow
                } else {
                    Write-Host "Created $($teamNumber - 1) team(s) successfully" -ForegroundColor Green
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

                        # Set load balancing algorithm to Dynamic for best performance
                        Set-VMSwitchTeam -Name "SET1" -LoadBalancingAlgorithm Dynamic

                        Rename-VMNetworkAdapter -Name "SET1" -NewName "vNIC-Mgmt-SET1" -ManagementOS
                        Write-Host "Created SET1 successfully with Dynamic load balancing" -ForegroundColor Green
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
    Start-ProgressStep "Windows Settings Configuration"

    # Disable Server Manager auto-start
    Get-ScheduledTask -TaskName ServerManager -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null

    # Set power plan to High Performance
    powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

    # Enable RDP
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

    # Disable Windows Firewall (temporarily for setup)
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

    # Set time zone
    Write-LogProgress "Setting time zone to: $TimeZone" "Info"
    try {
        Set-TimeZone -Name $TimeZone
        Write-LogProgress "Time zone set successfully" "Success"
    } catch {
        Write-LogProgress "Failed to set time zone: $_" "Warning"
        Write-LogProgress "Verify time zone name with 'Get-TimeZone -ListAvailable'" "Info"
    }

    # Enable LocalAccountTokenFilterPolicy for workgroup admin share access
    Write-LogProgress "Configuring LocalAccountTokenFilterPolicy for admin share access..." "Info"
    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if (!(Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name 'LocalAccountTokenFilterPolicy' -Value 1 -Type DWord -Force
        Write-LogProgress "LocalAccountTokenFilterPolicy enabled - admin shares accessible for local accounts" "Success"
    } catch {
        Write-LogProgress "Failed to set LocalAccountTokenFilterPolicy: $_" "Warning"
    }

    # Enable registry backup
    New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Configuration Manager\' `
                    -Name 'EnablePeriodicBackup' -PropertyType DWORD -Value 0x00000001 -Force -ErrorAction SilentlyContinue | Out-Null

    Write-Host "Windows settings configured" -ForegroundColor Green
    #endregion

    #region Step 9: Install Management Applications
    Start-ProgressStep "Management Applications Installation"

    # Check for WinGet
    $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetPath) {
        $apps = @(
            @{id = "Mozilla.Firefox"; name = "Firefox"},
            @{id = "7zip.7zip"; name = "7-Zip"},
            @{id = "Notepad++.Notepad++"; name = "Notepad++"},
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
        Start-ProgressStep "BitLocker Configuration"

        # Check if BitLocker features are installed
        Write-LogProgress "Checking BitLocker feature availability..." "Info"
        $bitlockerFeature = Get-WindowsFeature -Name BitLocker -ErrorAction SilentlyContinue
        $bitlockerAdminTools = Get-WindowsFeature -Name RSAT-Feature-Tools-BitLocker -ErrorAction SilentlyContinue

        Write-LogProgress "  BitLocker Feature: $($bitlockerFeature.InstallState)" "Debug"
        Write-LogProgress "  BitLocker Admin Tools: $($bitlockerAdminTools.InstallState)" "Debug"

        if (!$bitlockerFeature -or $bitlockerFeature.InstallState -ne "Installed") {
            Write-LogProgress "BitLocker feature not yet installed" "Warning"
            Write-Host "BitLocker configuration skipped - feature not installed" -ForegroundColor Yellow
            Write-Host "Install BitLocker feature and reboot before configuring" -ForegroundColor Yellow
        } elseif (!$bitlockerAdminTools -or $bitlockerAdminTools.InstallState -ne "Installed") {
            Write-LogProgress "BitLocker Admin Tools (RSAT) not yet installed" "Warning"
            Write-Host "BitLocker configuration skipped - admin tools not installed" -ForegroundColor Yellow
            Write-Host "Install RSAT-Feature-Tools-BitLocker and reboot before configuring" -ForegroundColor Yellow
        } else {
            # Both features installed, try to import module
            Write-LogProgress "BitLocker features installed, checking PowerShell module..." "Info"

            # Check if module files exist
            $modulePath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\BitLocker"
            if (Test-Path $modulePath) {
                Write-LogProgress "  BitLocker module path found: $modulePath" "Debug"
            } else {
                Write-LogProgress "  BitLocker module path NOT found: $modulePath" "Warning"
                Write-Host "BitLocker configuration skipped - module files not available" -ForegroundColor Yellow
                Write-Host "This usually means a REBOOT IS REQUIRED after BitLocker installation" -ForegroundColor Yellow
                Write-Host "Reboot the server and re-run this script to enable BitLocker" -ForegroundColor Yellow
                # Skip to end of BitLocker section
                continue
            }

            try {
                Import-Module BitLocker -ErrorAction Stop
                Write-LogProgress "BitLocker module loaded successfully" "Success"
            } catch {
                Write-LogProgress "Failed to import BitLocker module: $($_.Exception.Message)" "Error"
                Write-LogProgress "Module files may not be available until after reboot" "Warning"
                Write-Host "BitLocker configuration skipped - module import failed" -ForegroundColor Yellow
                Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host ""  -ForegroundColor Yellow
                Write-Host "SOLUTION: Reboot the server to complete BitLocker installation" -ForegroundColor Cyan
                Write-Host "Then re-run this script to configure BitLocker encryption" -ForegroundColor Cyan
            }
        }

        # Check if module was imported successfully
        if (Get-Module -Name BitLocker) {
            $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
            if ($tpm) {
                # Create directory for recovery keys
                $recoveryKeyPath = "$env:SystemDrive\BitLocker-Recovery-Keys"
                if (!(Test-Path $recoveryKeyPath)) {
                    New-Item -Path $recoveryKeyPath -ItemType Directory -Force | Out-Null
                }
                $recoveryFile = Join-Path $recoveryKeyPath "BitLocker-Recovery-Passwords-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').txt"

                # Enable BitLocker on OS drive
                $osDrive = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq "OperatingSystem" }
                if ($osDrive.ProtectionStatus -eq "Off") {
                    Write-Host "Enabling BitLocker on OS drive ($($osDrive.MountPoint))..."
                    Write-LogProgress "  Using TPM protector with auto-generated recovery password" "Info"

                    # Enable with TPM and skip hardware test to avoid reboot
                    Enable-BitLocker -MountPoint $osDrive.MountPoint `
                                    -TpmProtector `
                                    -EncryptionMethod XtsAes256 `
                                    -SkipHardwareTest `
                                    -UsedSpaceOnly

                    # Add auto-generated recovery password protector
                    $recoveryProtector = Add-BitLockerKeyProtector -MountPoint $osDrive.MountPoint `
                                                                   -RecoveryPasswordProtector

                    # Get the recovery password
                    $recoveryPassword = (Get-BitLockerVolume -MountPoint $osDrive.MountPoint).KeyProtector |
                                       Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } |
                                       Select-Object -First 1 -ExpandProperty RecoveryPassword

                    # Save recovery password to file
                    $outputText = @"
========================================
BitLocker Recovery Information
========================================
Computer: $env:COMPUTERNAME
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

OS DRIVE ($($osDrive.MountPoint))
Recovery Password: $recoveryPassword

"@
                    $outputText | Out-File -FilePath $recoveryFile -Encoding UTF8

                    Write-Host "BitLocker enabled on OS drive" -ForegroundColor Green
                    Write-Host "  Recovery password saved to: $recoveryFile" -ForegroundColor Cyan
                    Write-LogProgress "  Recovery Password: $recoveryPassword" "Info"
                } else {
                    Write-Host "BitLocker already enabled on OS drive" -ForegroundColor Green
                }

                # Enable on data drives with TPM auto-unlock (skip external/removable drives)
                $allDataVolumes = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq "Data" }

                # Filter out external/removable drives
                $dataVolumes = @()
                foreach ($vol in $allDataVolumes) {
                    try {
                        $partition = Get-Partition | Where-Object { $_.DriveLetter -eq $vol.MountPoint.TrimEnd(':') } | Select-Object -First 1
                        if ($partition) {
                            $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction SilentlyContinue

                            # Skip if disk is removable or USB
                            if ($disk.BusType -eq 'USB' -or $disk.BusType -eq 'SD' -or $disk.BusType -eq 'MMC') {
                                Write-LogProgress "  Skipping external drive $($vol.MountPoint) (BusType: $($disk.BusType))" "Info"
                                continue
                            }

                            # Include this volume
                            $dataVolumes += $vol
                        }
                    } catch {
                        Write-LogProgress "  Could not check if $($vol.MountPoint) is external: $_" "Warning"
                        # Include volume if we can't determine (safer than skipping internal drives)
                        $dataVolumes += $vol
                    }
                }

                if ($dataVolumes.Count -gt 0) {
                    Write-LogProgress "Found $($dataVolumes.Count) internal data volume(s) for BitLocker encryption" "Info"
                } else {
                    Write-LogProgress "No internal data volumes found to encrypt" "Info"
                }

                foreach ($volume in $dataVolumes) {
                    if ($volume.ProtectionStatus -eq "Off") {
                        Write-Host "Enabling BitLocker on $($volume.MountPoint) drive..."
                        Write-LogProgress "  Using TPM auto-unlock with recovery password" "Info"

                        # Enable with recovery password (no manual password needed)
                        Enable-BitLocker -MountPoint $volume.MountPoint `
                                        -RecoveryPasswordProtector `
                                        -EncryptionMethod XtsAes256 `
                                        -SkipHardwareTest `
                                        -UsedSpaceOnly

                        # Get the auto-generated recovery password
                        $dataRecoveryPassword = (Get-BitLockerVolume -MountPoint $volume.MountPoint).KeyProtector |
                                               Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } |
                                               Select-Object -First 1 -ExpandProperty RecoveryPassword

                        # Enable auto-unlock using TPM from OS drive
                        Enable-BitLockerAutoUnlock -MountPoint $volume.MountPoint

                        # Append to recovery file
                        $dataOutput = @"
DATA DRIVE ($($volume.MountPoint))
Recovery Password: $dataRecoveryPassword
Auto-Unlock: Enabled (TPM)

"@
                        $dataOutput | Out-File -FilePath $recoveryFile -Append -Encoding UTF8

                        Write-Host "BitLocker enabled on $($volume.MountPoint)" -ForegroundColor Green
                        Write-Host "  Auto-unlock enabled via TPM" -ForegroundColor Green
                        Write-Host "  Recovery password saved to: $recoveryFile" -ForegroundColor Cyan
                        Write-LogProgress "  Recovery Password: $dataRecoveryPassword" "Info"
                    }
                }

                if (Test-Path $recoveryFile) {
                    Write-Host ""
                    Write-Host "IMPORTANT: BitLocker recovery passwords saved to:" -ForegroundColor Yellow
                    Write-Host "  $recoveryFile" -ForegroundColor Yellow
                    Write-Host "Store this file securely - you'll need it to recover encrypted drives!" -ForegroundColor Yellow
                }
            } else {
                Write-Host "No TPM detected - skipping BitLocker" -ForegroundColor Yellow
            }
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

    # Check if network teams actually exist
    $existingTeams = Get-VMSwitch -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "SET*" }
    if ($existingTeams) {
        Write-Host "  Network: $($existingTeams.Count) SET Team(s) Configured" -ForegroundColor Green
        foreach ($team in $existingTeams) {
            $memberCount = ($team.NetAdapterInterfaceDescription | Measure-Object).Count
            Write-Host "    - $($team.Name): $memberCount NIC(s)" -ForegroundColor Gray
        }
    } elseif (!$SkipNetworkTeaming) {
        Write-Host "  Network: No teams created - manual configuration may be needed" -ForegroundColor Yellow
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