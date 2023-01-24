# Enable registry backup
New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Configuration Manager\' -Name 'EnablePeriodicBackup'  -PropertyType DWORD -Value 0x00000001 -Force -ea 'SilentlyContinue'

# Enable System Restore
Enable-ComputerRestore -drive $Env:SYSTEMDRIVE'\'