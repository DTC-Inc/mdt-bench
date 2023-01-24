Get-BitlockerVolume | Where -Property VolumeType -eq OperatingSystem | Enable-Bitlocker -TpmProtector -EncryptionMethod AES256
Get-BitlockerVolume | Where -Property VolumeType -eq OperatingSystem | Add-BitlockerKeyProtector -RecoveryPasswordProtector
Get-BitlockerVOlume | Where -Property VolumeType -ne OperatingSystem | Enable-Bitlocker -StartupKeyProtector -StartupKeyPath $Env:SYSTEMDRIVE\
Get-BitlockerVOlume | Where -Property VolumeType -ne OperatingSystem | Add-BitlockerKeyProtector -RecoveryPasswordProtector
Get-BitlockerVOlume | Where -Property VolumeType -ne OperatingSystem | Enable-BitLockerAutoUnlock	
