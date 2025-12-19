# MDT-Bench - Windows Server & Workstation Deployment Scripts

## 🎯 Overview

Comprehensive PowerShell deployment scripts for automated configuration of Windows Server 2025 and Windows 11 systems. These standalone scripts provide complete, production-ready setup for Hyper-V hosts, domain controllers, application servers, and workstations.

## ⚠️ System Requirements

**IMPORTANT:** These scripts are designed exclusively for:
- **Windows Server 2025** (21H2 or later)
- **Windows 11** (22H2 or later)

The scripts utilize WinGet package manager and modern PowerShell features only available in these versions.

## 📂 Script Inventory

| Script | Purpose | Target System |
|--------|---------|---------------|
| `Setup-HyperVHost-Standalone.ps1` | Complete Hyper-V host with SET networking | Server 2025 |
| `Setup-DomainController-Standalone.ps1` | Domain Controller with AD DS prep | Server 2025 |
| `Setup-AppServer-Standalone.ps1` | Application server with IIS/SQL options | Server 2025 |
| `Setup-BackupServer-Standalone.ps1` | Backup/DR server with Hyper-V & Storage Spaces | Server 2025 |
| `Setup-Workstation-Standalone.ps1` | Windows 11 with debloat and optimization | Windows 11 |

## 🚀 Quick Start

### Hyper-V Host Setup

```powershell
# Basic setup with all defaults
.\Setup-HyperVHost-Standalone.ps1

# Custom setup with specific options
.\Setup-HyperVHost-Standalone.ps1 `
    -TeamsOf 4 `                    # Create SET teams with 4 NICs each
    -AutoNICTeaming `                # Auto-team by PCIe card
    -SkipBitLocker `                 # Skip BitLocker configuration
    -SkipWindowsUpdate               # Skip Windows Updates
```

### Domain Controller Setup

```powershell
# Basic DC preparation
.\Setup-DomainController-Standalone.ps1

# With AD DS installation
.\Setup-DomainController-Standalone.ps1 `
    -InstallADDS `                  # Install AD DS role
    -DomainName "corp.local" `      # Specify domain name
    -NetBIOSName "CORP"             # Specify NetBIOS name
```

### Application Server Setup

```powershell
# Basic app server
.\Setup-AppServer-Standalone.ps1

# Full stack with IIS and SQL
.\Setup-AppServer-Standalone.ps1 `
    -InstallIIS `                   # Install IIS with all features
    -InstallSQL `                   # Install SQL Server Express
    -InstallDotNet                  # Install all .NET versions
```

### Backup Server Setup

```powershell
# Basic backup server with Hyper-V and Storage Spaces
.\Setup-BackupServer-Standalone.ps1

# Custom configuration
.\Setup-BackupServer-Standalone.ps1 `
    -StorageRedundancy "rrs" `      # Rack-redundant storage
    -SkipNetworkTeaming `           # Skip network teaming
    -InstallVeeam                   # Prepare for Veeam installation

# Note: Includes Hyper-V for Instant VM Recovery and testing
```

### Workstation Setup

```powershell
# Basic workstation setup
.\Setup-Workstation-Standalone.ps1

# Full optimization and debloat
.\Setup-Workstation-Standalone.ps1 `
    -RemoveDefaultApps `            # Remove Windows bloatware
    -RemoveOneDrive `               # Completely remove OneDrive
    -AggressiveDebloat `            # Maximum optimization
    -SkipBitLocker                  # Skip BitLocker
```

## 📋 Common Parameters

### All Scripts Support:
- `-SkipWindowsUpdate` - Skip Windows Update installation
- `-LogPath` - Custom log file path (default: `.\Logs\`)

### Hyper-V Specific:
- `-TeamsOf` - Number of NICs per SET team (2 or 4)
- `-AutoNICTeaming` - Auto-create teams by PCIe card
- `-SkipNetworkTeaming` - Skip SET team configuration
- `-SkipBitLocker` - Skip BitLocker configuration

### Workstation Specific:
- `-SkipDebloat` - Skip all debloat operations
- `-RemoveDefaultApps` - Remove default Windows apps
- `-RemoveOneDrive` - Completely remove OneDrive
- `-AggressiveDebloat` - Maximum performance optimization

## 🔧 Features

### Hyper-V Host Features
- **Intelligent NIC Teaming**: PCIe-aware SET team creation with visual port mapping
- **Storage Configuration**: Automatic partition setup for boot/data separation
- **Dell Hardware Support**: Auto-installs OpenManage on Dell servers
- **Hyper-V Optimization**: Configures storage paths and virtual switch settings

### Domain Controller Features
- **AD DS Preparation**: Full Active Directory setup guidance
- **DNS Configuration**: Automatic DNS role installation
- **DHCP Option**: Optional DHCP server installation
- **Security Baseline**: Implements DC security best practices

### Application Server Features
- **IIS Configuration**: Complete web server setup with all features
- **SQL Server Express**: Optional database server installation
- **.NET Framework**: All versions including 3.5 and 4.8
- **Application Directories**: Creates standard app deployment structure

### Workstation Features
- **Privacy Protection**: Blocks telemetry and tracking
- **Performance Optimization**: SSD detection and tuning
- **Bloatware Removal**: Removes unnecessary Windows apps
- **Security Hardening**: Disables unnecessary services

## 📦 Package Management

All scripts use **WinGet** (Windows Package Manager) for software installation:

```powershell
# Applications installed via WinGet:
- Mozilla Firefox
- 7-Zip
- Visual Studio Code
- Visual C++ Redistributables
- Google Chrome (workstations)
- Adobe Reader (workstations)
- VLC Media Player (workstations)
- Notepad++ (all systems)
- Git (app servers)
```

For custom applications with hard-coded URLs (Dell tools, etc.), the scripts download directly from vendor URLs.

## 🔐 Security Considerations

- **Firewall**: Scripts disable Windows Firewall - re-enable after configuration
- **BitLocker**: Optional on all systems (use `-SkipBitLocker` to bypass)
- **Telemetry**: Workstation script blocks tracking (can skip with `-SkipDebloat`)
- **Updates**: Always install latest updates unless explicitly skipped

## 📊 Logging

All scripts generate detailed logs:
- Default location: `.\Logs\[ScriptName]-Standalone-[Timestamp].log`
- Custom location: Use `-LogPath` parameter
- Includes all actions, errors, and warnings
- Color-coded console output for easy monitoring

## ⚡ Performance Tips

### NIC Teaming Best Practices
1. Use interactive mode (default) to ensure adjacent ports are teamed
2. Connect ports on the same PCIe card for optimal performance
3. Create separate teams for management and VM traffic

### Storage Configuration
- Answer "y" for dedicated boot disk if you have separate OS/Data drives
- Script auto-creates D: drive for data/VMs
- Hyper-V VMs automatically stored on D: if available

## 🐛 Troubleshooting

### Common Issues

**NIC Teaming Fails**
- Ensure Hyper-V role is installed first
- Check that all NICs are on compatible firmware
- Verify network cables are properly connected

**WinGet Not Found**
- Confirm Windows 11/Server 2025 version
- Run `winget --version` to verify installation
- Install App Installer from Microsoft Store if missing

**BitLocker Errors**
- Verify TPM 2.0 is enabled in BIOS
- Check that drives are not already encrypted
- Use `-SkipBitLocker` if TPM unavailable

## 🔄 Update History

- **v2.0** - Consolidated standalone scripts, WinGet integration
- **v1.5** - Enhanced NIC teaming with PCIe detection
- **v1.0** - Initial modular script collection

## 📝 License

Property of DTC Inc. Internal use only.

## 💡 Support

For issues or questions:
- Review log files first (`.\Logs\`)
- Check Windows Event Viewer for system errors
- Ensure you're running as Administrator
- Verify Windows 11/Server 2025 compatibility

---

**Note**: These scripts make significant system changes. Always test in a non-production environment first and ensure you have proper backups before running on production systems.