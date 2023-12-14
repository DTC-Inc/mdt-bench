# Install Choco

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

$AppList = 'firefox','7zip','vscode','vcredist-all','googlechrome'

$AppList | ForEach-Object -Process {choco install $_ -y}
$AppList | ForEach-Object -Process {choco upgrade $_ -y}
