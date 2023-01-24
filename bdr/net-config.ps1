Get-VMNetworkadapter -managementOS  | Where-Object -property "name" -notlike "Container NIC*" | Remove-VMNetworkAdapter
Get-VMSwitch | Where-Object -property name -notlike "Default Switch" | Remove-VMSwitch -force
Get-NetSwitchteam| Remove-NetSwitchTeam
$toTeam = Get-NetAdapter | Where-Object -property interfaceDescription -like "Intel*" | Select-Object -expandProperty name
New-NetSwitchTeam -name TEAM1 -teamMembers $toTeam
New-VMSwitch -name TEAM0 -netAdapterName TEAM1
Rename-VMNetworkAdapter -name TEAM1 -newName vNIC1-TEAM1 -managementOS
ping 8.8.8.8 -n 30