# Disk formatting selection
$errorCatch = $true

while ($errorCatch -eq $true) {
  $inputBoot = Read-Host "Does this server have a dedicated boot disk? (y or n)"
  Write-Host "You chose $inputBoot."

  if ($inputBoot -eq "y" -or $inputBoot -eq "n") {
    if ($inputBoot -eq "y") {
      # Expand OS partition
      $maxSize = (Get-PartitionSupportedSize -DriveLetter C).sizeMax
      Resize-Partition -DriveLetter C -size $maxSize

      # Create data1 partition
      $dataDisk = Get-Disk | Where-Object -Property isBoot -NE $true | Select-Object -ExpandProperty number
      Initialize-Disk -partitionStyle GPT -number $dataDisk
      New-Partition -DiskNumber $dataDisk -useMaximumSize -DriveLetter D
      Format-Volume -fileSystem NTFS -DriveLetter D
      Get-Volume | Where-Object -Property driveLetter -EQ D | Set-Volume -newFileSystemLabel data1

    } else {
      # Expand OS partition
      Resize-Partition -DriveLetter C -size 120GB

      # Create data1 partition
      New-Partition -DiskNumber 0 -useMaximumSize -DriveLetter D
      Format-Volume -fileSystem NTFS -DriveLetter D
      Get-Volume | Where-Object -Property driveLetter -EQ D | Set-Volume -newFileSystemLabel data1

    }
    $errorCatch = $false

  } else {
    Write-Host "Input not accepted. Try again."

  }

}