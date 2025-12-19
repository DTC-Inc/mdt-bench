# RMM Deployment Guide for MDT-Bench Scripts

## Overview

The v2 scripts are designed for deployment through RMM systems (NinjaRMM, ConnectWise Automate, Datto RMM, etc.) using environment variables instead of PowerShell parameters. This allows for easier automation and standardization across different client environments.

## Environment Variable Pattern

All configuration is done through environment variables with the prefix `MDT_`. This follows MSP best practices for avoiding hardcoded values and allowing dynamic configuration per client or device.

### Variable Format
```
MDT_[SETTING_NAME]=[VALUE]
```

## Server Naming Convention

All servers follow the pattern: **`RoleXX`** where:
- **Role** = 2-letter role code (see table below)
- **XX** = 2-digit sequence number (01-99)

### Server Role Codes

| Script | Role Code | Examples | Description |
|--------|-----------|----------|-------------|
| Setup-HyperVHost | **HV** | HV01, HV02, HV03 | Hyper-V Host |
| Setup-DomainController | **DC** | DC01, DC02 | Domain Controller |
| Setup-AppServer | **AP** | AP01, AP02, AP03 | Application Server |
| Setup-BackupServer | **BK** | BK01, BK02 | Backup/DR Server |
| Setup-Workstation | N/A | N/A | Workstations keep existing names |

### Other Common Role Codes (Reference)

| Role Code | Server Type | Examples |
|-----------|-------------|----------|
| **FS** | File Server | FS01, FS02 |
| **DB** | Database Server | DB01, DB02 |
| **RD** | Remote Desktop Server | RD01, RD02 |
| **WS** | Web Server | WS01, WS02 |
| **EX** | Exchange Server | EX01, EX02 |

## Standard Variables (All Scripts)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MDT_SERVER_SEQUENCE` | String | Prompt | Server sequence number (01-99) |
| `MDT_COMPANY_NAME` | String | "DTC" | Company name for branding/customization |
| `MDT_SKIP_WINDOWS_UPDATE` | Boolean | false | Skip Windows Update installation |
| `MDT_SKIP_BITLOCKER` | Boolean | false | Skip BitLocker configuration |
| `MDT_LOG_PATH` | String | "C:\Logs\MDT" | Directory for script logs |
| `MDT_STORAGE_REDUNDANCY` | String | "ers" | Storage naming (ers/rrs/zrs/grs) |

## Script-Specific Variables

### Hyper-V Host (`Setup-HyperVHost-Standalone-v2.ps1`)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MDT_SKIP_NETWORK_TEAMING` | Boolean | false | Skip network team configuration |
| `MDT_TEAMS_OF` | Integer | 2 | NICs per SET team (2 or 4) |
| `MDT_AUTO_NIC_TEAMING` | Boolean | false | Auto-team by PCIe card |

### Domain Controller (`Setup-DomainController-Standalone-v2.ps1`)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MDT_INSTALL_ADDS` | Boolean | false | Install AD DS role |
| `MDT_DOMAIN_NAME` | String | "corp.local" | Domain name for new forest |
| `MDT_NETBIOS_NAME` | String | "CORP" | NetBIOS domain name |
| `MDT_INSTALL_DHCP` | Boolean | false | Install DHCP Server role |

### Application Server (`Setup-AppServer-Standalone-v2.ps1`)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MDT_INSTALL_IIS` | Boolean | false | Install IIS with all features |
| `MDT_INSTALL_SQL` | Boolean | false | Install SQL Server Express |
| `MDT_INSTALL_DOTNET` | Boolean | false | Install all .NET versions |

### Backup Server (`Setup-BackupServer-Standalone-v2.ps1`)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MDT_SKIP_STORAGE_SPACES` | Boolean | false | Skip Storage Spaces config |
| `MDT_SKIP_NETWORK_TEAMING` | Boolean | false | Skip network teaming |
| `MDT_INSTALL_VEEAM` | Boolean | false | Prepare for Veeam install |

### Workstation (`Setup-Workstation-Standalone-v2.ps1`)

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `MDT_SKIP_DEBLOAT` | Boolean | false | Skip all debloat operations |
| `MDT_REMOVE_DEFAULT_APPS` | Boolean | false | Remove Windows default apps |
| `MDT_REMOVE_ONEDRIVE` | Boolean | false | Completely remove OneDrive |
| `MDT_AGGRESSIVE_DEBLOAT` | Boolean | false | Maximum optimization |

## RMM Configuration Examples

### NinjaRMM

1. **Create Script Fields:**
   - Go to Administration > Scripts
   - Add new PowerShell script
   - Add Script Variables for each MDT_ variable needed

2. **Script Variable Setup:**
```
Name: MDT_COMPANY_NAME
Type: String
Default: {{NINJA_ORGANIZATION_NAME}}

Name: MDT_SKIP_BITLOCKER
Type: Dropdown
Options: true, false
Default: false
```

3. **Script Content:**
```powershell
# Set environment variables from Ninja fields
$env:MDT_COMPANY_NAME = $env:NINJA_ORGANIZATION_NAME
$env:MDT_SKIP_BITLOCKER = "$(MDT_SKIP_BITLOCKER)"
$env:MDT_STORAGE_REDUNDANCY = "$(MDT_STORAGE_REDUNDANCY)"

# Download and run script
$scriptUrl = "https://raw.githubusercontent.com/DTC-Inc/mdt-bench/main/Setup-HyperVHost-Standalone-v2.ps1"
Invoke-Expression ((New-Object Net.WebClient).DownloadString($scriptUrl))
```

### ConnectWise Automate

1. **Create Script:**
   - Scripts > New Script
   - Add Parameters for each setting

2. **Script Steps:**
```
Step 1: Variable Set
Variable: %MDT_COMPANY_NAME%
Value: @ClientName@

Step 2: Variable Set
Variable: %MDT_SKIP_BITLOCKER%
Value: @SkipBitLocker@

Step 3: PowerShell Command
[Environment]::SetEnvironmentVariable("MDT_COMPANY_NAME", "%MDT_COMPANY_NAME%")
[Environment]::SetEnvironmentVariable("MDT_SKIP_BITLOCKER", "%MDT_SKIP_BITLOCKER%")
& ".\Setup-HyperVHost-Standalone-v2.ps1"
```

### Datto RMM

1. **Create Component:**
   - Components > New Component
   - Component Type: PowerShell

2. **Input Variables:**
```yaml
- name: CompanyName
  type: string
  default: "[COMPANY_NAME]"

- name: SkipBitLocker
  type: boolean
  default: false
```

3. **Script:**
```powershell
# Map Datto variables to MDT variables
$env:MDT_COMPANY_NAME = $env:CompanyName
$env:MDT_SKIP_BITLOCKER = if ($env:SkipBitLocker -eq $true) { "true" } else { "false" }

# Run setup script
& ".\Setup-HyperVHost-Standalone-v2.ps1"
```

### Generic PowerShell (Direct)

```powershell
# Set all required variables
$env:MDT_COMPANY_NAME = "Contoso"
$env:MDT_SKIP_BITLOCKER = "true"
$env:MDT_TEAMS_OF = "4"
$env:MDT_STORAGE_REDUNDANCY = "rrs"
$env:MDT_AUTO_NIC_TEAMING = "true"

# Run the script
.\Setup-HyperVHost-Standalone-v2.ps1
```

## Global Custom Fields Strategy

For sensitive or client-specific data, use RMM Global Custom Fields:

### Example: Storage Configuration by Client Type

**NinjaRMM Global Custom Fields:**
- Field Name: `ClientStorageRedundancy`
- Field Type: Dropdown
- Options: ers, rrs, zrs, grs
- Apply to: Organization

**In Script:**
```powershell
# Get from Ninja custom field
$storageType = Ninja-Property-Get ClientStorageRedundancy
$env:MDT_STORAGE_REDUNDANCY = $storageType
```

### Example: Feature Flags by Client Size

**Small Clients (< 25 users):**
```
MDT_STORAGE_REDUNDANCY = "ers"
MDT_SKIP_NETWORK_TEAMING = "true"
MDT_AGGRESSIVE_DEBLOAT = "true"
```

**Enterprise Clients (100+ users):**
```
MDT_STORAGE_REDUNDANCY = "grs"
MDT_SKIP_NETWORK_TEAMING = "false"
MDT_TEAMS_OF = "4"
MDT_AGGRESSIVE_DEBLOAT = "false"
```

## Logging and Monitoring

All scripts log to `C:\Logs\MDT\` by default:

- `HyperVHost-Setup-YYYY-MM-DD-HHMMSS.log`
- `DomainController-Setup-YYYY-MM-DD-HHMMSS.log`
- `AppServer-Setup-YYYY-MM-DD-HHMMSS.log`
- `BackupServer-Setup-YYYY-MM-DD-HHMMSS.log`
- `Workstation-Setup-YYYY-MM-DD-HHMMSS.log`

### RMM Log Collection

**NinjaRMM:**
```powershell
# After script completion
$logFile = Get-ChildItem "C:\Logs\MDT" -Filter "*.log" |
           Sort-Object CreationTime -Descending |
           Select-Object -First 1

# Upload to Ninja
Ninja-File-Upload $logFile.FullName
```

**ConnectWise Automate:**
```
File Copy: C:\Logs\MDT\*.log
To: LTShare\Logs\%ComputerName%\
```

## Best Practices

1. **Never Hardcode Secrets**: Use RMM secure storage for any passwords or keys
2. **Use Client Variables**: Leverage RMM's built-in variables (client name, location, etc.)
3. **Test with Defaults**: Ensure scripts work with all default values
4. **Log Everything**: Comprehensive logging helps with troubleshooting
5. **Validate Input**: Scripts validate all environment variables before use
6. **Fail Gracefully**: Clear error messages that RMM can capture

## Boolean Values

Boolean environment variables accept:
- True: `"true"`, `"1"`, `"yes"`
- False: `"false"`, `"0"`, `"no"`, or empty/unset

## Troubleshooting

### Check Current Configuration
```powershell
Get-ChildItem env:MDT_* | Format-Table Name, Value
```

### Test Mode
```powershell
# Set test mode to see what would happen
$env:MDT_TEST_MODE = "true"
.\Setup-HyperVHost-Standalone-v2.ps1
```

### Debug Logging
```powershell
# Enable verbose logging
$env:MDT_DEBUG = "true"
.\Setup-HyperVHost-Standalone-v2.ps1
```

## Migration from v1 (Parameter-based)

### Old Way (v1):
```powershell
.\Setup-HyperVHost-Standalone.ps1 `
    -SkipBitLocker `
    -TeamsOf 4 `
    -StorageRedundancy "rrs"
```

### New Way (v2):
```powershell
$env:MDT_SKIP_BITLOCKER = "true"
$env:MDT_TEAMS_OF = "4"
$env:MDT_STORAGE_REDUNDANCY = "rrs"
.\Setup-HyperVHost-Standalone-v2.ps1
```

## Security Notes

- Environment variables are cleared after script execution
- No sensitive data should be logged
- Use RMM's secure credential storage for any passwords
- Scripts run with local admin privileges only

---

*Last Updated: December 2024*
*DTC Inc - MSP Automation Team*