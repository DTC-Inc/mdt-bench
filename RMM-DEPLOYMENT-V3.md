# RMM Deployment Guide - V3 MSP Template Scripts

## Overview

Version 3 scripts follow the MSP Script Library template standards for complete RMM compatibility. These scripts are **fully non-interactive** when running from an RMM platform.

## Key Changes in V3

### 1. RMM Detection
Scripts detect RMM execution via the `$RMM` variable:
- `$RMM = 1` → RMM mode (non-interactive)
- `$RMM` not set → Interactive mode (prompts allowed)

### 2. No User Interaction in RMM Mode
- **No Read-Host prompts** when `$RMM = 1`
- All decisions use pre-set variables or defaults
- Missing required variables cause clean exit with error message

### 3. Standard MSP Template Structure
```powershell
## SECTION 1: RMM VARIABLE DECLARATION
## List all RMM variables here as comments

## SECTION 2: INPUT HANDLING
if ($RMM -ne 1) {
    # Interactive mode - prompt for input
} else {
    # RMM mode - use variables or fail
}

## SECTION 3: MAIN SCRIPT LOGIC
Start-Transcript -Path $LogPath
# Actual work happens here
Stop-Transcript
```

## Required RMM Variables

### All Server Scripts (HV, DC, AP, BK)
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `$RMM` | **YES** | - | Must be set to `1` for RMM execution |
| `$ServerSequence` | **YES** | - | Server number (1-99), becomes HV01, DC01, etc. |
| `$CompanyName` | No | "DTC" | Company name for branding |
| `$SkipWindowsUpdate` | No | `$false` | Skip Windows Updates |
| `$SkipBitLocker` | No | `$false` | Skip BitLocker configuration |

### Hyper-V Host Specific
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `$SkipNetworkTeaming` | No | `$false` | Skip SET team configuration |
| `$TeamsOf` | No | 2 | NICs per SET team (2 or 4) |
| `$AutoNICTeaming` | No | `$false` | Auto-configure teams by PCIe card |
| `$StorageRedundancy` | No | "ers" | Storage naming (ers/rrs/zrs/grs) |
| `$AcceptRAIDWarning` | No | `$false` | Accept single RAID disk configuration |

### Domain Controller Specific
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `$InstallADDS` | No | `$false` | Install AD DS role |
| `$DomainName` | No | "corp.local" | Domain name for new forest |
| `$NetBIOSName` | No | "CORP" | NetBIOS domain name |
| `$InstallDHCP` | No | `$false` | Install DHCP Server role |

### Application Server Specific
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `$InstallIIS` | No | `$false` | Install IIS with all features |
| `$InstallSQL` | No | `$false` | Install SQL Server Express |
| `$InstallDotNet` | No | `$false` | Install all .NET versions |

### Backup Server Specific
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `$SkipStorageSpaces` | No | `$false` | Skip Storage Spaces configuration |
| `$InstallVeeam` | No | `$false` | Prepare for Veeam installation |
| `$StorageRedundancy` | No | "ers" | Storage naming convention |
| `$AcceptSingleDisk` | No | `$false` | Accept single disk for storage |

### Workstation Specific
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `$RMM` | **YES** | - | Must be set to `1` for RMM execution |
| `$SkipDebloat` | No | `$false` | Skip all debloat operations |
| `$RemoveDefaultApps` | No | `$false` | Remove Windows default apps |
| `$RemoveOneDrive` | No | `$false` | Completely remove OneDrive |
| `$AggressiveDebloat` | No | `$false` | Maximum optimization |

## RMM Platform Configuration Examples

### NinjaRMM

1. **Create Script**:
   - Administration → Library → Scripts → Add New Script
   - Script Language: PowerShell
   - Architecture: Windows (64-bit)

2. **Add Script Variables**:
```powershell
# Required
$RMM = 1
$ServerSequence = "[[ServerSequence]]"

# Optional with defaults
$CompanyName = "[[CompanyName|DTC]]"
$SkipWindowsUpdate = [[SkipWindowsUpdate|0]]
$SkipBitLocker = [[SkipBitLocker|0]]
$AutoNICTeaming = [[AutoNICTeaming|1]]
$AcceptRAIDWarning = [[AcceptRAIDWarning|0]]
```

3. **Script Content**:
```powershell
# Download and execute
$scriptUrl = "https://raw.githubusercontent.com/DTC-Inc/mdt-bench/main/Setup-HyperVHost-Standalone-v3.ps1"
Invoke-Expression ((New-Object Net.WebClient).DownloadString($scriptUrl))
```

### ConnectWise Automate

1. **Create Script**:
   - Automation → Scripts → New Script

2. **Script Steps**:
```
Step 1: Variable Set - Global
Variable: %RMM%
Value: 1

Step 2: Variable Set - Global
Variable: %ServerSequence%
Value: @FieldInput@

Step 3: Variable Set - Global
Variable: %AcceptRAIDWarning%
Value: 1

Step 4: PowerShell Command
Script:
$RMM = 1
$ServerSequence = "%ServerSequence%"
$AcceptRAIDWarning = $true
& "C:\Temp\Setup-HyperVHost-Standalone-v3.ps1"
```

### Datto RMM

1. **Create Component**:
   - Components → New Component
   - Type: PowerShell Script

2. **Input Variables**:
```yaml
inputs:
  - name: ServerSequence
    type: string
    required: true
    description: "Server number (01-99)"

  - name: AcceptRAIDWarning
    type: boolean
    default: false
    description: "Accept single RAID configuration"
```

3. **Script**:
```powershell
# Map Datto variables
$RMM = 1
$ServerSequence = $env:ServerSequence
$AcceptRAIDWarning = [bool]$env:AcceptRAIDWarning

# Run script
& ".\Setup-HyperVHost-Standalone-v3.ps1"
```

## Handling RAID Warnings in RMM

When the script detects suboptimal RAID configuration (OS and Data on same virtual disk):

### Interactive Mode
- User is prompted to continue or cancel
- Can choose to reconfigure RAID first

### RMM Mode
- Script will **fail by default** for safety
- Set `$AcceptRAIDWarning = $true` to continue anyway
- Error message tells you exactly what to set

Example error:
```
Single RAID disk detected and AcceptRAIDWarning not set!
Set $AcceptRAIDWarning=$true in RMM to continue with this configuration
```

## Automatic Restart Handling

When configuration requires a restart:

### Interactive Mode
- Prompts user "Restart now? (y/n)"
- User controls restart timing

### RMM Mode
- Automatic restart after 60 seconds
- Logs warning about pending restart
- Shutdown command: `shutdown /r /t 60`

## Log Locations

### Interactive Mode
- Primary: `C:\Windows\logs\[ScriptName]-[Timestamp].log`
- Full transcript of all operations

### RMM Mode
- If `$RMMScriptPath` is set: `$RMMScriptPath\logs\[ScriptName]-[Timestamp].log`
- Fallback: `C:\Windows\logs\[ScriptName]-[Timestamp].log`

## Error Handling

### RMM Mode Failures
Scripts will cleanly exit with specific error messages:
- Missing required variables
- Invalid configuration values
- Hardware incompatibilities
- RAID configuration issues

Exit codes:
- `0` = Success
- `1` = Failure (check transcript for details)

## Best Practices for RMM Deployment

1. **Always Set Required Variables**
   - `$RMM = 1` (mandatory)
   - `$ServerSequence` for servers (mandatory)

2. **Test in Lab First**
   - Run interactively to understand prompts
   - Test RMM mode with all variables set

3. **Review RAID Configuration**
   - Check if single RAID disk is acceptable
   - Set `$AcceptRAIDWarning` if continuing

4. **Monitor Logs**
   - Collect transcript logs after execution
   - Check for warnings even if successful

5. **Handle Restarts**
   - Plan for 60-second auto-restart
   - Consider maintenance windows

## Migration from V2

### Key Differences
| Feature | V2 (Environment Variables) | V3 (RMM Variables) |
|---------|----------------------------|-------------------|
| Detection | `MDT_*` env vars | `$RMM` variable |
| Required | All optional | `$RMM` and `$ServerSequence` required |
| Prompts | Some prompts remain | Zero prompts when `$RMM=1` |
| Template | Custom | MSP Script Library standard |

### Variable Mapping
```powershell
# V2 Environment Variables → V3 RMM Variables
MDT_SERVER_SEQUENCE      → $ServerSequence
MDT_COMPANY_NAME        → $CompanyName
MDT_SKIP_WINDOWS_UPDATE → $SkipWindowsUpdate
MDT_SKIP_BITLOCKER     → $SkipBitLocker
MDT_TEAMS_OF           → $TeamsOf
MDT_AUTO_NIC_TEAMING   → $AutoNICTeaming
MDT_STORAGE_REDUNDANCY → $StorageRedundancy
```

## Quick Start Examples

### Deploy Hyper-V Host via NinjaRMM
```powershell
$RMM = 1
$ServerSequence = "01"  # Becomes HV01
$AutoNICTeaming = $true # Auto-configure network
$AcceptRAIDWarning = $true # Accept current RAID
& ".\Setup-HyperVHost-Standalone-v3.ps1"
```

### Deploy Domain Controller via ConnectWise
```powershell
$RMM = 1
$ServerSequence = "01"  # Becomes DC01
$InstallADDS = $true
$DomainName = "corp.contoso.com"
$NetBIOSName = "CORP"
& ".\Setup-DomainController-Standalone-v3.ps1"
```

### Deploy Workstation via Datto RMM
```powershell
$RMM = 1
$RemoveDefaultApps = $true
$RemoveOneDrive = $true
$AggressiveDebloat = $true
& ".\Setup-Workstation-Standalone-v3.ps1"
```

## Support Matrix

| Script | Windows Server 2025 | Windows 11 | RMM Mode | Interactive |
|--------|-------------------|------------|----------|-------------|
| Hyper-V Host | ✅ | ❌ | ✅ | ✅ |
| Domain Controller | ✅ | ❌ | ✅ | ✅ |
| App Server | ✅ | ❌ | ✅ | ✅ |
| Backup Server | ✅ | ❌ | ✅ | ✅ |
| Workstation | ❌ | ✅ | ✅ | ✅ |

---

**Note**: V3 scripts are designed for production RMM deployment. Always test in your environment first!