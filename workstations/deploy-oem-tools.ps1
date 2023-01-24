$Manufacturer = Get-CimInstance -ClassName Win32_ComputerSystem | Select -ExpandProperty Manufacturer

if ($Manufacturer -like "Dell*") { 
	# Dell
	$progressPreference = 'SilentlyContinue'
	wget https://s3.us-west-002.backblazeb2.com/public-dtc/repo/vendors/dell/command/command-config-latest.EXE -OutFile $env:windir\temp\command-config-latest.exe
	wget https://s3.us-west-002.backblazeb2.com/public-dtc/repo/vendors/dell/command/command-update-latest.EXE -OutFile $env:windir\temp\command-update-latest.exe

	Start-Process -FilePath "$env:windir\temp\command-config-latest.exe" -args "/s" -Wait
	Start-Process -FilePath "$env:windir\temp\command-update-latest.exe" -args "/s" -Wait
}