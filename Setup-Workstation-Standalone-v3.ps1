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
    - $NewComputerName: New computer name (optional, leave blank to keep current name)
    - $SkipWindowsUpdate: Skip Windows Updates (default: false)
    - $SkipBitLocker: Skip BitLocker configuration (default: false)
    - $SkipDebloat: Skip all debloat operations (default: false)
    - $RemoveOneDrive: Completely remove OneDrive (default: false)
    - $RemoveDefaultApps: Remove Windows default apps (default: false)
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

## SECTION 1: RMM VARIABLE DECLARATION
## PLEASE COMMENT YOUR VARIABLES DIRECTLY BELOW HERE IF YOU'RE RUNNING FROM A RMM
## $RMM = 1
## $CompanyName = "DTC"
## $NewComputerName = ""                # Leave blank to keep current name
## $SkipWindowsUpdate = $false
## $SkipBitLocker = $false
## $SkipDebloat = $false
## $RemoveOneDrive = $false
## $RemoveDefaultApps = $false

## SECTION 2: INPUT HANDLING

# Helper function to convert strings to booleans (RMM platforms often pass strings)
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

# Initialize variables with defaults if not set
if ($null -eq $CompanyName) { $CompanyName = "DTC" }
if ($null -eq $NewComputerName) { $NewComputerName = "" }
if ($null -eq $SkipWindowsUpdate) { $SkipWindowsUpdate = $false }
if ($null -eq $SkipBitLocker) { $SkipBitLocker = $false }
if ($null -eq $SkipDebloat) { $SkipDebloat = $false }
if ($null -eq $RemoveOneDrive) { $RemoveOneDrive = $false }
if ($null -eq $RemoveDefaultApps) { $RemoveDefaultApps = $false }

# Convert string values to proper booleans (in case RMM passes strings)
$SkipWindowsUpdate = ConvertTo-Boolean $SkipWindowsUpdate
$SkipBitLocker = ConvertTo-Boolean $SkipBitLocker
$SkipDebloat = ConvertTo-Boolean $SkipDebloat
$RemoveOneDrive = ConvertTo-Boolean $RemoveOneDrive
$RemoveDefaultApps = ConvertTo-Boolean $RemoveDefaultApps

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
    Write-Host "Current Computer Name: $env:COMPUTERNAME" -ForegroundColor Green
    Write-Host ""

    # Get company name
    $input = Read-Host "Enter company name (default: DTC)"
    if (![string]::IsNullOrEmpty($input)) { $CompanyName = $input }

    # Ask about computer renaming
    $response = Read-Host "Rename this computer? (y/n, default: n)"
    if ($response -eq 'y') {
        $input = Read-Host "Enter new computer name"
        if (![string]::IsNullOrEmpty($input)) {
            $NewComputerName = $input
            Write-Host "Computer will be renamed to: $NewComputerName" -ForegroundColor Yellow
        }
    }

    # Ask about debloat options
    $response = Read-Host "Remove Windows default apps? (y/n, default: n)"
    if ($response -eq 'y') { $RemoveDefaultApps = $true }

    $response = Read-Host "Remove OneDrive completely? (y/n, default: n)"
    if ($response -eq 'y') { $RemoveOneDrive = $true }

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
    Write-Host "Current Computer Name: $env:COMPUTERNAME" -ForegroundColor Green
    if (![string]::IsNullOrEmpty($NewComputerName)) {
        Write-Host "Will be renamed to: $NewComputerName" -ForegroundColor Yellow
    }

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
Write-Host "Current Computer Name: $env:COMPUTERNAME"
if (![string]::IsNullOrEmpty($NewComputerName)) {
    Write-Host "New Computer Name: $NewComputerName" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Configuration Options:" -ForegroundColor Yellow
Write-Host "  Rename Computer: $(if (![string]::IsNullOrEmpty($NewComputerName)) { $NewComputerName } else { 'No' })"
Write-Host "  Skip Debloat: $SkipDebloat"
Write-Host "  Remove Default Apps: $RemoveDefaultApps"
Write-Host "  Remove OneDrive: $RemoveOneDrive"
Write-Host "  Skip Windows Update: $SkipWindowsUpdate"
Write-Host "  Skip BitLocker: $SkipBitLocker"
Write-Host ""

# Error handling
$ErrorActionPreference = "Stop"
$RestartRequired = $false

try {
    #region Computer Renaming
    if (![string]::IsNullOrEmpty($NewComputerName)) {
        Write-Host "Step 0: Computer Renaming..." -ForegroundColor Cyan

        if ($env:COMPUTERNAME -ne $NewComputerName) {
            Write-Host "Renaming computer from '$env:COMPUTERNAME' to '$NewComputerName'..." -ForegroundColor Yellow
            try {
                Rename-Computer -NewName $NewComputerName -Force -ErrorAction Stop
                Write-Host "Computer renamed successfully to '$NewComputerName'" -ForegroundColor Green
                Write-Host "A restart is required for the name change to take effect" -ForegroundColor Yellow
                $RestartRequired = $true
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
        Write-Host ""
    }
    #endregion

    #region Windows Configuration
    Write-Host "Step 1: Configuring Windows Settings..." -ForegroundColor Cyan
    try {
        # Enable registry backup
        New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Configuration Manager\' `
                        -Name 'EnablePeriodicBackup' -PropertyType DWORD -Value 0x00000001 -Force -ErrorAction SilentlyContinue | Out-Null

        # Enable System Restore
        Enable-ComputerRestore -Drive "$env:SYSTEMDRIVE\"

        # Detect if this is a laptop
        $chassisTypes = (Get-CimInstance -ClassName Win32_SystemEnclosure).ChassisTypes
        # Laptop chassis types: 8=Portable, 9=Laptop, 10=Notebook, 14=Sub Notebook, 31=Convertible, 32=Detachable
        $laptopChassisTypes = @(8, 9, 10, 14, 31, 32)
        $IsLaptop = $false
        foreach ($type in $chassisTypes) {
            if ($laptopChassisTypes -contains $type) {
                $IsLaptop = $true
                break
            }
        }
        Write-Host "Device Type: $(if ($IsLaptop) { 'Laptop' } else { 'Desktop' })" -ForegroundColor Cyan

        #region Power Management Configuration
        Write-Host "Configuring power management settings..." -ForegroundColor Cyan

        # Get all power schemes
        $powerSchemes = powercfg /list | Where-Object { $_ -match "GUID: ([a-f0-9\-]+)" } | ForEach-Object {
            if ($_ -match "GUID: ([a-f0-9\-]+)\s+\((.+?)\)(?:\s+\*)?") {
                [PSCustomObject]@{
                    GUID = $matches[1]
                    Name = $matches[2].Trim()
                    IsActive = $_ -match "\*$"
                }
            }
        }

        Write-Host "Found $($powerSchemes.Count) power scheme(s)" -ForegroundColor Gray

        # Disable Fast Startup globally via registry
        Write-Host "  Disabling Fast Startup..." -ForegroundColor White
        $fastStartupRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
        if (!(Test-Path $fastStartupRegPath)) {
            New-Item -Path $fastStartupRegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $fastStartupRegPath -Name "HiberbootEnabled" -Value 0 -Type DWord

        # Hibernation: Disable on desktops, keep on laptops
        if ($IsLaptop) {
            Write-Host "  Keeping hibernation enabled (laptop detected)" -ForegroundColor White
        } else {
            Write-Host "  Disabling hibernation (desktop detected)..." -ForegroundColor White
            powercfg /hibernate off 2>&1 | Out-Null
        }

        # Configure power settings for each scheme
        foreach ($scheme in $powerSchemes) {
            Write-Host "  Configuring power scheme: $($scheme.Name)" -ForegroundColor Gray

            # Power setting GUIDs
            # SUB_SLEEP = 238C9FA8-0AAD-41ED-83F4-97BE242C8F20
            # HYBRIDSLEEP = 94ac6d29-73ce-41a6-809f-6363ba21b47e
            # STANDBYIDLE = 29f6c1db-86da-48c5-9fdb-f2b67b1f44da
            # UNATTENDSLEEP = 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0
            # WAKETIMERS = BD3B718A-0680-4D9D-8AB2-E1D2B4AC806D
            # SUB_DISK = 0012EE47-9041-4B5D-9B77-535FBA8B1442
            # DISKIDLE = 6738E2C4-E8A5-4A42-B16A-E040E769756E
            # SUB_BUTTONS = 4F971E89-EEBD-4455-A8DE-9E59040E7347
            # LIDACTION = 5ca83367-6e45-459f-a27b-476b1d01c936
            # SUB_BATTERY = E73A048D-BF27-4F12-9731-8B2076E8891F
            # CRITBATTERYACTION = 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546
            # SUB_USB = 2A737441-1930-4402-8D77-B2BEBBA308A3
            # USBSELECTIVESUSPEND = 48E6B7A6-50F5-4782-A5D4-53BB8F07E226
            # SUB_PCIEXPRESS = 501A4D13-42AF-4429-9FD1-A8218C268E20
            # ASPM = EE12F906-D277-404B-B6DA-E5FA1A576DF5
            # SUB_RADIO = 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1
            # RADIOPS = 12bbebe6-58d6-4636-95bb-3217ef867c1a
            # SUB_MULTIMEDIA = 9596fb26-9850-41fd-ac3e-f7c3c00afd4b
            # VIDEOQUALITYBIAS = 10778347-1370-4ee0-8bbd-33bdacaade49
            # WHENPLAYINGVIDEO = 34C7B99F-9A6D-4b3c-8DC7-B6693B78CEF4

            # Disable hybrid sleep
            powercfg /setacvalueindex $($scheme.GUID) 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 94ac6d29-73ce-41a6-809f-6363ba21b47e 0 | Out-Null
            powercfg /setdcvalueindex $($scheme.GUID) 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 94ac6d29-73ce-41a6-809f-6363ba21b47e 0 | Out-Null

            # Disable hard disk turn off
            powercfg /setacvalueindex $($scheme.GUID) 0012EE47-9041-4B5D-9B77-535FBA8B1442 6738E2C4-E8A5-4A42-B16A-E040E769756E 0 | Out-Null
            powercfg /setdcvalueindex $($scheme.GUID) 0012EE47-9041-4B5D-9B77-535FBA8B1442 6738E2C4-E8A5-4A42-B16A-E040E769756E 0 | Out-Null

            # Disable automatic sleep
            powercfg /setacvalueindex $($scheme.GUID) 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0 | Out-Null
            powercfg /setdcvalueindex $($scheme.GUID) 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0 | Out-Null

            # Disable unattended sleep timeout
            powercfg /setacvalueindex $($scheme.GUID) 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 0 | Out-Null
            powercfg /setdcvalueindex $($scheme.GUID) 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 0 | Out-Null

            # Lid close action: Sleep (for laptops)
            # 0=Do nothing, 1=Sleep, 2=Hibernate, 3=Shut down
            powercfg /setacvalueindex $($scheme.GUID) 4F971E89-EEBD-4455-A8DE-9E59040E7347 5CA83367-6E45-459F-A27B-476B1D01C936 1 | Out-Null
            powercfg /setdcvalueindex $($scheme.GUID) 4F971E89-EEBD-4455-A8DE-9E59040E7347 5CA83367-6E45-459F-A27B-476B1D01C936 1 | Out-Null

            # Critical battery action: Hibernate for laptops, Shutdown for desktops
            # 0=Do nothing, 1=Sleep, 2=Hibernate, 3=Shut down
            if ($IsLaptop) {
                powercfg /setdcvalueindex $($scheme.GUID) E73A048D-BF27-4F12-9731-8B2076E8891F 637EA02F-BBCB-4015-8E2C-A1C7B9C0B546 2 | Out-Null
            } else {
                powercfg /setdcvalueindex $($scheme.GUID) E73A048D-BF27-4F12-9731-8B2076E8891F 637EA02F-BBCB-4015-8E2C-A1C7B9C0B546 3 | Out-Null
            }

            # Disable USB selective suspend
            powercfg /setacvalueindex $($scheme.GUID) 2A737441-1930-4402-8D77-B2BEBBA308A3 48E6B7A6-50F5-4782-A5D4-53BB8F07E226 0 | Out-Null
            powercfg /setdcvalueindex $($scheme.GUID) 2A737441-1930-4402-8D77-B2BEBBA308A3 48E6B7A6-50F5-4782-A5D4-53BB8F07E226 0 | Out-Null

            # Disable PCIE Link State Power Management (ASPM)
            powercfg /setacvalueindex $($scheme.GUID) 501A4D13-42AF-4429-9FD1-A8218C268E20 EE12F906-D277-404B-B6DA-E5FA1A576DF5 0 | Out-Null
            powercfg /setdcvalueindex $($scheme.GUID) 501A4D13-42AF-4429-9FD1-A8218C268E20 EE12F906-D277-404B-B6DA-E5FA1A576DF5 0 | Out-Null

            # Enable wake timers
            powercfg /setacvalueindex $($scheme.GUID) 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 BD3B718A-0680-4D9D-8AB2-E1D2B4AC806D 1 2>&1 | Out-Null
            powercfg /setdcvalueindex $($scheme.GUID) 238C9FA8-0AAD-41ED-83F4-97BE242C8F20 BD3B718A-0680-4D9D-8AB2-E1D2B4AC806D 1 2>&1 | Out-Null

            # Wireless adapter: Maximum performance
            powercfg /setacvalueindex $($scheme.GUID) 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0 2>&1 | Out-Null
            powercfg /setdcvalueindex $($scheme.GUID) 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0 2>&1 | Out-Null

            # Video playback: Maximum quality
            powercfg /setacvalueindex $($scheme.GUID) 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 10778347-1370-4ee0-8bbd-33bdacaade49 1 2>&1 | Out-Null
            powercfg /setdcvalueindex $($scheme.GUID) 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 10778347-1370-4ee0-8bbd-33bdacaade49 1 2>&1 | Out-Null

            # Multimedia: Optimize video quality
            powercfg /setacvalueindex $($scheme.GUID) 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 34C7B99F-9A6D-4b3c-8DC7-B6693B78CEF4 0 2>&1 | Out-Null
            powercfg /setdcvalueindex $($scheme.GUID) 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 34C7B99F-9A6D-4b3c-8DC7-B6693B78CEF4 0 2>&1 | Out-Null
        }

        Write-Host "Power management configured" -ForegroundColor Green
        #endregion

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

            # Clean up desktop shortcuts created by installers
            Write-Host "Cleaning up desktop shortcuts..." -ForegroundColor Cyan
            $desktopPaths = @(
                "$env:PUBLIC\Desktop",
                "$env:USERPROFILE\Desktop"
            )
            $shortcutsRemoved = 0
            foreach ($desktopPath in $desktopPaths) {
                if (Test-Path $desktopPath) {
                    $shortcuts = Get-ChildItem -Path $desktopPath -Filter "*.lnk" -ErrorAction SilentlyContinue
                    foreach ($shortcut in $shortcuts) {
                        Remove-Item -Path $shortcut.FullName -Force -ErrorAction SilentlyContinue
                        $shortcutsRemoved++
                    }
                }
            }
            Write-Host "Removed $shortcutsRemoved desktop shortcut(s)" -ForegroundColor Green
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

        # Check if Windows edition supports BitLocker (Pro, Enterprise, Education)
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $supportsBitLocker = $osInfo.Caption -match "Pro|Enterprise|Education"

        if (!$supportsBitLocker) {
            Write-Host "BitLocker not available on this Windows edition ($($osInfo.Caption))" -ForegroundColor Yellow
            Write-Host "BitLocker requires Windows 11 Pro, Enterprise, or Education" -ForegroundColor Yellow
        } else {
            # Check if TPM is present and ready
            $tpm = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue

            if ($tpm -and $tpm.IsEnabled_InitialValue) {
                Write-Host "TPM detected and enabled" -ForegroundColor Green

                # Create directory for recovery keys
                $recoveryKeyPath = "$env:SystemDrive\BitLocker-Recovery-Keys"
                if (!(Test-Path $recoveryKeyPath)) {
                    New-Item -Path $recoveryKeyPath -ItemType Directory -Force | Out-Null
                }
                $recoveryFile = Join-Path $recoveryKeyPath "BitLocker-Recovery-Passwords-$(Get-Date -Format 'yyyy-MM-dd-HHmmss').txt"

                # Initialize recovery file
                $outputText = @"
========================================
BitLocker Recovery Information
========================================
Computer: $env:COMPUTERNAME
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

"@
                $outputText | Out-File -FilePath $recoveryFile -Encoding UTF8

                try {
                    # Enable BitLocker on OS drive
                    $osDrive = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq "OperatingSystem" }

                    if ($osDrive.ProtectionStatus -eq "Off") {
                        Write-Host "Enabling BitLocker on OS drive ($($osDrive.MountPoint))..." -ForegroundColor Cyan
                        Write-Host "  Using XtsAes256 encryption with TPM protector" -ForegroundColor Gray

                        # Enable with TPM and skip hardware test to avoid reboot requirement
                        Enable-BitLocker -MountPoint $osDrive.MountPoint `
                                        -TpmProtector `
                                        -EncryptionMethod XtsAes256 `
                                        -SkipHardwareTest `
                                        -UsedSpaceOnly

                        # Add auto-generated recovery password protector
                        Add-BitLockerKeyProtector -MountPoint $osDrive.MountPoint -RecoveryPasswordProtector

                        # Get the recovery password
                        $recoveryPassword = (Get-BitLockerVolume -MountPoint $osDrive.MountPoint).KeyProtector |
                                           Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } |
                                           Select-Object -First 1 -ExpandProperty RecoveryPassword

                        # Append to recovery file
                        $osOutput = @"
OS DRIVE ($($osDrive.MountPoint))
Recovery Password: $recoveryPassword

"@
                        $osOutput | Out-File -FilePath $recoveryFile -Append -Encoding UTF8

                        Write-Host "BitLocker enabled on OS drive" -ForegroundColor Green
                        Write-Host "  Recovery password saved to: $recoveryFile" -ForegroundColor Cyan
                    } else {
                        Write-Host "BitLocker already enabled on OS drive" -ForegroundColor Green
                    }

                    # Enable on data drives with auto-unlock (skip external/removable drives)
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
                                    Write-Host "  Skipping external drive $($vol.MountPoint) (BusType: $($disk.BusType))" -ForegroundColor Gray
                                    continue
                                }

                                # Include this volume
                                $dataVolumes += $vol
                            }
                        } catch {
                            Write-Host "  Could not check if $($vol.MountPoint) is external: $_" -ForegroundColor Yellow
                            # Include volume if we can't determine (safer than skipping internal drives)
                            $dataVolumes += $vol
                        }
                    }

                    if ($dataVolumes.Count -gt 0) {
                        Write-Host "Found $($dataVolumes.Count) internal data volume(s) for BitLocker encryption" -ForegroundColor Gray
                    }

                    foreach ($volume in $dataVolumes) {
                        if ($volume.ProtectionStatus -eq "Off") {
                            Write-Host "Enabling BitLocker on $($volume.MountPoint) drive..." -ForegroundColor Cyan

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

                            # Enable auto-unlock
                            Enable-BitLockerAutoUnlock -MountPoint $volume.MountPoint

                            # Append to recovery file
                            $dataOutput = @"
DATA DRIVE ($($volume.MountPoint))
Recovery Password: $dataRecoveryPassword
Auto-Unlock: Enabled

"@
                            $dataOutput | Out-File -FilePath $recoveryFile -Append -Encoding UTF8

                            Write-Host "BitLocker enabled on $($volume.MountPoint)" -ForegroundColor Green
                            Write-Host "  Auto-unlock enabled" -ForegroundColor Green
                            Write-Host "  Recovery password saved to: $recoveryFile" -ForegroundColor Cyan
                        }
                    }

                    if (Test-Path $recoveryFile) {
                        Write-Host ""
                        Write-Host "IMPORTANT: BitLocker recovery passwords saved to:" -ForegroundColor Yellow
                        Write-Host "  $recoveryFile" -ForegroundColor Yellow
                        Write-Host "Store this file securely - you'll need it to recover encrypted drives!" -ForegroundColor Yellow
                    }

                } catch {
                    Write-Host "BitLocker configuration error: $_" -ForegroundColor Yellow
                }
            } else {
                Write-Host "No TPM detected or TPM not enabled - skipping BitLocker" -ForegroundColor Yellow
                Write-Host "BitLocker requires a TPM 2.0 chip for automatic encryption" -ForegroundColor Yellow
            }
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