<#
.SYNOPSIS
    Complete Standalone Application Server Setup Script - MSP RMM Template Version
.DESCRIPTION
    Single-file setup script for Application Server VMs with all configurations
    consolidated. Follows MSP Script Library template for RMM deployment.
    Fully non-interactive when $RMM=1.
.NOTES
    Author: DTC Inc
    Version: 3.0 MSP Template
    Date: 2025-12-19

    RMM Variables:
    - $RMM: Set to 1 for RMM mode (no prompts)
    - $ServerSequence: Server sequence number (01-99) REQUIRED
    - $CompanyName: Company name for branding (default: DTC)
    - $SkipWindowsUpdate: Skip Windows Updates (default: false)
    - $SkipNetworkTeaming: Skip network team configuration (default: false)
    - $SkipBitLocker: Skip BitLocker configuration (default: false)
    - $InstallIIS: Install IIS with all features (default: false)
    - $InstallSQL: Install SQL Server Express (default: false)
    - $InstallDotNet: Install all .NET versions (default: false)
    - $HasDedicatedBootDisk: Server has separate boot disk (default: false)
    - $AcceptSingleDisk: Accept single disk configuration (default: false)
#>

#Requires -RunAsAdministrator
#Requires -Version 5.1

## SECTION 1: RMM VARIABLE DECLARATION
## PLEASE COMMENT YOUR VARIABLES DIRECTLY BELOW HERE IF YOU'RE RUNNING FROM A RMM
## $RMM = 1
## $ServerSequence = "01"
## $CompanyName = "DTC"
## $SkipWindowsUpdate = $false
## $SkipNetworkTeaming = $false
## $SkipBitLocker = $false
## $InstallIIS = $false
## $InstallSQL = $false
## $InstallDotNet = $false
## $HasDedicatedBootDisk = $false
## $AcceptSingleDisk = $false

## SECTION 2: INPUT HANDLING
# Initialize variables with defaults if not set
if ($null -eq $CompanyName) { $CompanyName = "DTC" }
if ($null -eq $SkipWindowsUpdate) { $SkipWindowsUpdate = $false }
if ($null -eq $SkipNetworkTeaming) { $SkipNetworkTeaming = $false }
if ($null -eq $SkipBitLocker) { $SkipBitLocker = $false }
if ($null -eq $InstallIIS) { $InstallIIS = $false }
if ($null -eq $InstallSQL) { $InstallSQL = $false }
if ($null -eq $InstallDotNet) { $InstallDotNet = $false }
if ($null -eq $HasDedicatedBootDisk) { $HasDedicatedBootDisk = $false }
if ($null -eq $AcceptSingleDisk) { $AcceptSingleDisk = $false }

# Server Role Code for Application Server
$ServerRole = "AP"
$ScriptLogName = "AppServer-Setup-v3"

# Detect RMM mode
if ($RMM -ne 1) {
    # Interactive mode - prompt for required inputs
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Application Server Setup Script (v3)" -ForegroundColor Cyan
    Write-Host "Interactive Mode" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Get server sequence
    $ValidInput = $false
    while (!$ValidInput) {
        $sequence = Read-Host "Enter the sequence number for this Application Server (1-99)"
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

    # Ask about installation options
    $response = Read-Host "Install IIS Web Server? (y/n, default: n)"
    if ($response -eq 'y') { $InstallIIS = $true }

    $response = Read-Host "Install SQL Server Express? (y/n, default: n)"
    if ($response -eq 'y') { $InstallSQL = $true }

    $response = Read-Host "Install all .NET Framework versions? (y/n, default: n)"
    if ($response -eq 'y') { $InstallDotNet = $true }

    # Ask about storage configuration
    $response = Read-Host "Does this server have a dedicated boot disk? (y/n, default: n)"
    if ($response -eq 'y') { $HasDedicatedBootDisk = $true }

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
        $Description = "Application Server setup for $CompanyName"
    }

    # Set log path for interactive mode
    $LogPath = "$ENV:WINDIR\logs"
} else {
    # RMM mode - use variables passed from RMM
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Application Server Setup Script (v3)" -ForegroundColor Cyan
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

    $Description = "RMM-initiated Application Server setup for $CompanyName"

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
Write-Host "  Install IIS: $InstallIIS"
Write-Host "  Install SQL: $InstallSQL"
Write-Host "  Install .NET: $InstallDotNet"
Write-Host "  Has Dedicated Boot Disk: $HasDedicatedBootDisk"
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

    #region Storage Configuration
    Write-Host ""
    Write-Host "Step 1: Configuring Storage..." -ForegroundColor Cyan
    try {
        # Get current disk configuration
        $bootDisk = Get-Disk | Where-Object { $_.IsBoot -eq $true }
        $dataDisk = Get-Disk | Where-Object { $_.IsBoot -ne $true } | Select-Object -First 1

        if ($HasDedicatedBootDisk -or $null -ne $dataDisk) {
            Write-Host "Configuring with dedicated boot disk..."

            # Expand OS partition to maximum
            try {
                $partition = Get-Partition -DriveLetter C
                $maxSize = (Get-PartitionSupportedSize -DriveLetter C).SizeMax
                $currentSize = $partition.Size

                if (($maxSize - $currentSize) -gt 1GB) {
                    Write-Host "Expanding C: drive to maximum size..."
                    Resize-Partition -DriveLetter C -Size $maxSize
                } else {
                    Write-Host "C: drive already at maximum size"
                }
            } catch {
                Write-Host "Could not expand C: drive: $_" -ForegroundColor Yellow
            }

            # Initialize and configure data disk
            if ($null -ne $dataDisk -and $dataDisk.PartitionStyle -eq 'RAW') {
                Write-Host "Initializing data disk..."
                Initialize-Disk -Number $dataDisk.Number -PartitionStyle GPT -Confirm:$false
                New-Partition -DiskNumber $dataDisk.Number -UseMaximumSize -DriveLetter D
                Format-Volume -DriveLetter D -FileSystem NTFS -NewFileSystemLabel "data1" -Confirm:$false
                Write-Host "Data disk configured as D: drive" -ForegroundColor Green
            } elseif (Test-Path D:\) {
                Write-Host "D: drive already exists"
            }
        } else {
            # Single disk configuration
            if ($RMM -eq 1 -and !$AcceptSingleDisk) {
                Write-Host "ERROR: Single disk configuration detected!" -ForegroundColor Red
                Write-Host "Set `$AcceptSingleDisk=`$true in RMM to continue with this configuration" -ForegroundColor Red
                exit 1
            }

            if ($RMM -ne 1) {
                Write-Host "WARNING: Single disk configuration detected!" -ForegroundColor Yellow
                Write-Host "This will create OS (120GB) and Data partitions on the same disk." -ForegroundColor Yellow
                $response = Read-Host "Continue? (y/n)"
                if ($response -ne 'y') {
                    Write-Host "Storage configuration cancelled by user" -ForegroundColor Yellow
                    exit 1
                }
            }

            Write-Host "Configuring single disk with OS and Data partitions..."

            # Check if D: already exists
            if (!(Test-Path D:\)) {
                # Shrink C: to 120GB if needed
                $partition = Get-Partition -DriveLetter C
                if ($partition.Size -gt 130GB) {
                    Write-Host "Resizing C: partition to 120GB..."
                    Resize-Partition -DriveLetter C -Size 120GB
                }

                # Create data partition
                New-Partition -DiskNumber $bootDisk.Number -UseMaximumSize -DriveLetter D
                Format-Volume -DriveLetter D -FileSystem NTFS -NewFileSystemLabel "data1" -Confirm:$false
                Write-Host "Data partition created as D: drive" -ForegroundColor Green
            } else {
                Write-Host "D: drive already exists"
            }
        }
    } catch {
        Write-Host "Storage configuration error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Filesystem Configuration
    Write-Host ""
    Write-Host "Step 2: Configuring Filesystem..." -ForegroundColor Cyan
    try {
        if (Test-Path D:\) {
            New-Item -Path D:\ -Name 'repo' -ItemType Directory -Force | Out-Null
            New-Item -Path D:\ -Name 'apps' -ItemType Directory -Force | Out-Null
            New-Item -Path D:\ -Name 'data' -ItemType Directory -Force | Out-Null
            Write-Host "Created folder structure on D: drive" -ForegroundColor Green
        }
    } catch {
        Write-Host "Filesystem configuration error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Network Configuration
    Write-Host ""
    Write-Host "Step 3: Configuring Network..." -ForegroundColor Cyan
    if (!$SkipNetworkTeaming) {
        try {
            # Get connected NICs
            $nics = Get-NetAdapter | Where-Object {
                $_.Status -eq 'Up' -and
                $_.DriverFileName -notlike "usb*" -and
                $_.Name -notlike "vEthernet*" -and
                $_.InterfaceDescription -notlike "*Hyper-V*"
            }

            if ($nics.Count -ge 2) {
                if ($RMM -eq 1) {
                    Write-Host "Multiple NICs detected. Creating network team..."
                    # Auto-create team in RMM mode
                    $nicNames = $nics | Select-Object -ExpandProperty Name
                    New-NetLbfoTeam -Name TEAM1 -TeamMembers $nicNames -LoadBalancingAlgorithm Dynamic -TeamingMode SwitchIndependent -Confirm:$false
                    Write-Host "Network team TEAM1 created successfully" -ForegroundColor Green
                } else {
                    Write-Host "Multiple NICs detected. Would you like to configure network teaming?"
                    $response = Read-Host "Configure network team? (y/n)"
                    if ($response -eq 'y') {
                        Write-Host "Available network adapters:"
                        $nics | Format-Table Name, Status, LinkSpeed, InterfaceDescription

                        Write-Host "Please connect NICs to switch and press Enter when ready..."
                        Read-Host

                        $nicNames = $nics | Select-Object -ExpandProperty Name
                        New-NetLbfoTeam -Name TEAM1 -TeamMembers $nicNames -LoadBalancingAlgorithm Dynamic -TeamingMode SwitchIndependent -Confirm:$false
                        Write-Host "Network team TEAM1 created successfully" -ForegroundColor Green
                    }
                }
            } else {
                Write-Host "Insufficient NICs for teaming (found: $($nics.Count))"
            }
        } catch {
            Write-Host "Network configuration error: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Skipping network teaming configuration"
    }
    #endregion

    #region User Profile Configuration
    Write-Host ""
    Write-Host "Step 4: Configuring User Profiles..." -ForegroundColor Cyan
    try {
        # Clear Start Menu
        $Url = 'https://s3.us-west-002.backblazeb2.com/public-dtc/repo/config/windows/start-menu-cleared.xml'
        $outFile = "$env:WINDIR\temp\LayoutModification.xml"
        Invoke-WebRequest -Uri $Url -OutFile $outFile -UseBasicParsing

        Copy-Item $outFile -Destination "$env:LOCALAPPDATA\Microsoft\Windows\Shell" -Force
        Copy-Item $outFile -Destination "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell" -Force

        Write-Host "User profile configuration completed" -ForegroundColor Green
    } catch {
        Write-Host "User profile configuration error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Windows Configuration
    Write-Host ""
    Write-Host "Step 5: Configuring Windows Settings..." -ForegroundColor Cyan
    try {
        # Disable Firewall
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

        # Set machine inactivity limit to 900 seconds
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name 'InactivityTimeoutSecs' -PropertyType DWORD -Value 0x00000384 -Force -ErrorAction SilentlyContinue | Out-Null

        # Disable ServerManager from auto starting
        Get-ScheduledTask -TaskName ServerManager -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null

        # Enable registry backup
        New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Configuration Manager\' -Name 'EnablePeriodicBackup' -PropertyType DWORD -Value 0x00000001 -Force -ErrorAction SilentlyContinue | Out-Null

        Write-Host "Windows configuration completed" -ForegroundColor Green
    } catch {
        Write-Host "Windows configuration error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Deploy Windows Features
    Write-Host ""
    Write-Host "Step 6: Installing Windows Features..." -ForegroundColor Cyan
    try {
        # Install OpenSSH
        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 | Out-Null
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null

        Start-Service sshd
        Set-Service -Name sshd -StartupType 'Automatic'
        Set-NetFirewallRule -Name OpenSSH-Server-In-TCP -Profile Private,Domain

        # Set PowerShell as default shell
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null

        # Install .NET Framework if requested
        if ($InstallDotNet) {
            Write-Host "Installing .NET Framework features..."
            Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -NoRestart | Out-Null
            Enable-WindowsOptionalFeature -Online -FeatureName NetFx4-AdvSrvs -All -NoRestart | Out-Null
            Enable-WindowsOptionalFeature -Online -FeatureName NetFx4Extended-ASPNET45 -All -NoRestart | Out-Null
            Write-Host ".NET Framework installed successfully" -ForegroundColor Green
        }

        Write-Host "Windows features installed" -ForegroundColor Green
    } catch {
        Write-Host "Feature deployment error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Install IIS
    if ($InstallIIS) {
        Write-Host ""
        Write-Host "Step 7: Installing IIS and Web Features..." -ForegroundColor Cyan
        try {
            # Install IIS with common features
            $features = @(
                'IIS-WebServerRole',
                'IIS-WebServer',
                'IIS-CommonHttpFeatures',
                'IIS-HttpErrors',
                'IIS-HttpRedirect',
                'IIS-ApplicationDevelopment',
                'IIS-NetFxExtensibility45',
                'IIS-HealthAndDiagnostics',
                'IIS-HttpLogging',
                'IIS-Security',
                'IIS-RequestFiltering',
                'IIS-Performance',
                'IIS-WebServerManagementTools',
                'IIS-IIS6ManagementCompatibility',
                'IIS-Metabase',
                'IIS-ManagementConsole',
                'IIS-BasicAuthentication',
                'IIS-WindowsAuthentication',
                'IIS-StaticContent',
                'IIS-DefaultDocument',
                'IIS-DirectoryBrowsing',
                'IIS-ASPNET45'
            )

            Enable-WindowsOptionalFeature -Online -FeatureName $features -All -NoRestart | Out-Null

            # Create application pool directories
            if (Test-Path D:\) {
                New-Item -Path "D:\inetpub" -ItemType Directory -Force | Out-Null
                New-Item -Path "D:\inetpub\wwwroot" -ItemType Directory -Force | Out-Null
                New-Item -Path "D:\inetpub\logs" -ItemType Directory -Force | Out-Null
            }

            Write-Host "IIS and web features installed successfully" -ForegroundColor Green
        } catch {
            Write-Host "IIS installation error: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host ""
        Write-Host "Step 7: Skipping IIS installation" -ForegroundColor Gray
    }
    #endregion

    #region Deploy OEM Tools
    Write-Host ""
    Write-Host "Step 8: Installing OEM Tools..." -ForegroundColor Cyan
    try {
        $Manufacturer = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Manufacturer

        if ($Manufacturer -like "Dell*") {
            Write-Host "Dell hardware detected - installing OpenManage"

            # Download URLs for Dell tools
            $omsaUrl = "https://dl.dell.com/FOLDER11337880M/1/Windows_OMSA_11.0.1.0_A00.exe"
            $ismUrl = "https://dl.dell.com/FOLDER11034445M/1/iDRAC-Service-Module-5.3.0.0_Windows_x64.exe"
            $dsuUrl = "https://dl.dell.com/FOLDER11689994M/1/Systems-Management_Application_NVD8W_WN64_2.0.2.3_A00.EXE"

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

            # Download and install DSU
            Write-Host "Downloading Dell System Update..."
            Invoke-WebRequest -Uri $dsuUrl -OutFile "$env:WINDIR\temp\DSU_Setup.exe" -UseBasicParsing
            Write-Host "Installing Dell System Update..."
            Start-Process -FilePath "$env:WINDIR\temp\DSU_Setup.exe" -ArgumentList "/s" -Wait -NoNewWindow

            Write-Host "Dell OpenManage installation completed" -ForegroundColor Green
        } else {
            Write-Host "Non-Dell hardware - skipping OEM tools"
        }
    } catch {
        Write-Host "OEM tools deployment error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region Deploy Applications
    Write-Host ""
    Write-Host "Step 9: Installing Applications..." -ForegroundColor Cyan
    try {
        # Check if WinGet is available
        $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
        if ($wingetPath) {
            # Install common applications
            $apps = @(
                @{id = "Mozilla.Firefox"; name = "Firefox"},
                @{id = "7zip.7zip"; name = "7-Zip"},
                @{id = "Microsoft.VisualStudioCode"; name = "Visual Studio Code"},
                @{id = "Microsoft.VCRedist.2015+.x64"; name = "Visual C++ Redistributable"},
                @{id = "Notepad++.Notepad++"; name = "Notepad++"},
                @{id = "Git.Git"; name = "Git"}
            )

            foreach ($app in $apps) {
                Write-Host "Installing $($app.name)..."
                winget install --id $app.id --exact --silent --accept-package-agreements --accept-source-agreements
            }

            # Install SQL Server if requested
            if ($InstallSQL) {
                Write-Host "Installing SQL Server Express..."
                winget install --id Microsoft.SQLServer.2022.Express --exact --silent --accept-package-agreements --accept-source-agreements

                Write-Host "Installing SQL Server Management Studio..."
                winget install --id Microsoft.SQLServerManagementStudio --exact --silent --accept-package-agreements --accept-source-agreements
            }

            Write-Host "Applications installed" -ForegroundColor Green
        } else {
            Write-Host "WinGet not available - skipping application installation" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Application deployment error: $_" -ForegroundColor Yellow
    }
    #endregion

    #region BitLocker Configuration
    if (!$SkipBitLocker) {
        Write-Host ""
        Write-Host "Step 10: Configuring BitLocker..." -ForegroundColor Cyan
        try {
            # Check if BitLocker is available
            $bitlockerFeature = Get-WindowsFeature -Name BitLocker -ErrorAction SilentlyContinue
            if ($bitlockerFeature -and $bitlockerFeature.InstallState -eq 'Installed') {
                # Enable BitLocker on C: drive
                $blStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
                if ($blStatus -and $blStatus.VolumeStatus -eq 'FullyDecrypted') {
                    Write-Host "Enabling BitLocker on C: drive..."
                    Enable-BitLocker -MountPoint "C:" -RecoveryPasswordProtector -SkipHardwareTest
                    Write-Host "BitLocker enabled on C: drive" -ForegroundColor Green
                } else {
                    Write-Host "BitLocker already configured or not available on C: drive"
                }
            } else {
                Write-Host "BitLocker feature not installed"
            }
        } catch {
            Write-Host "BitLocker configuration error: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host ""
        Write-Host "Step 10: Skipping BitLocker configuration" -ForegroundColor Gray
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
    Write-Host "Application Server Setup Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Server Configuration:" -ForegroundColor Cyan
    Write-Host "  Name: $NewComputerName"
    Write-Host "  Company: $CompanyName"
    Write-Host ""

    if ($InstallIIS -or $InstallSQL -or $InstallDotNet) {
        Write-Host "Installed Components:" -ForegroundColor Cyan
        if ($InstallIIS) {
            Write-Host "  ✓ IIS Web Server" -ForegroundColor Green
            Write-Host "    - Default: C:\inetpub\wwwroot"
            if (Test-Path D:\) {
                Write-Host "    - Alternative: D:\inetpub\wwwroot"
            }
        }
        if ($InstallSQL) {
            Write-Host "  ✓ SQL Server Express" -ForegroundColor Green
            Write-Host "  ✓ SQL Server Management Studio" -ForegroundColor Green
        }
        if ($InstallDotNet) {
            Write-Host "  ✓ .NET Framework (all versions)" -ForegroundColor Green
        }
        Write-Host ""
    }

    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Restart server to apply all changes"
    Write-Host "  2. Configure application-specific settings"
    Write-Host "  3. Set up database connections if required"
    Write-Host "  4. Configure firewall rules for applications"
    Write-Host "  5. Join to domain if required"
    Write-Host "  6. Configure backup solutions"
    Write-Host ""
    Write-Host "Log file: $LogFile"

    # Handle restart
    if ($RestartRequired) {
        Write-Host ""
        Write-Host "RESTART REQUIRED" -ForegroundColor Yellow

        if ($RMM -eq 1) {
            Write-Host "RMM Mode: Automatic restart in 60 seconds..." -ForegroundColor Yellow
            Write-Host "Run 'shutdown /a' to cancel" -ForegroundColor Yellow
            shutdown /r /t 60 /c "Application Server setup complete. Restarting in 60 seconds..."
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