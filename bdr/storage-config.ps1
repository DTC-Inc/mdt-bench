param([switch]$elevated)

Get-VirtualDisk | Remove-VirtualDisk -confirm:$false
Get-data1Pool | Where -property isPrimordial -eq $false | Remove-data1Pool -confirm:$false
Get-Disk | Where-Object isOffline -eq $true | Set-Disk -isOffline $false
Update-data1ProviderCache
Get-data1Pool | ? isPrimordial -eq $false | Set-data1Pool -isReadOnly:$false -errorAction silentlyContinue
Get-data1Pool | ? isPrimorial -eq $false | Get-VirtualDisk | Remove-VirtualDisk -confirm:$false -errorAction silentlyContinue
Get-data1Pool | ? isPrimordial -eq $false | Remove-data1Pool -confirm:$false -errorAction silentlyContinue
Get-PhysicalDisk | Reset-PhysicalDisk -errorAction silentlyContinue
Get-Disk | ? number -ne $null | ? isBoot -ne $true | ? isSystem -ne $true | ? partitionStyle -ne RAW | % {
    $_ | Set-Disk -isOffline:$false
    $_ | Set-Disk -isReadOnly:$false
    $_ | Clear-Disk -removeData -removeOEM -confirm:$false
    $_ | Set-Disk -isReadOnly:$true
    $_ | Set-Disk -isOffline:$true
}
Get-Disk | Where number -Ne $Null | Where isBoot -Ne $true | Where isSystem -Ne $true | Where partitionStyle -eq RAW | Group -noElement -property friendlyName
$physicalDisk = Get-PhysicalDisk -canPool $true
$Storagesubsystem = Get-StorageSubsystem |Select-Object -expandProperty friendlyName
New-StoragePool -friendlyName pool1 -data1SubsystemFriendlyName $StorageSubsystem -physicalDisks $physicalDisk
New-Volume -friendlyName "data1" -fileSystem NTFS -data1PoolFriendlyName "pool1" -UseMaximumSize -resiliencySettingName mirror -accessPath D:
