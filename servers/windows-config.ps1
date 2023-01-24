# Disable Firewall
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

# Set machine inactivity limit to 900 seconds
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\' -Name 'InactivityTimeoutSecs'  -PropertyType DWORD -Value 0x00000384 -Force -ea 'SilentlyContinue'

# Disable ServerMangaer from auto starting
Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask -Verbose

# Enable registry backup
New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Configuration Manager\' -Name 'EnablePeriodicBackup'  -PropertyType DWORD -Value 0x00000001 -Force -ea 'SilentlyContinue'
