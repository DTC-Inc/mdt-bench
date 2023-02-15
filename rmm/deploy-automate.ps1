#description: Install the ConnectWise AUTOMATE RMM agent.
#execution mode: Individual
#tags: Nerdio, ConnectWise

<#
Notes:
This script will install the CONNECTWISE AUTOMATE AGENT. 
The script will first qualify if another Automate agent is already
installed on the computer. If the existing agent belongs to different 
Automate server, it will automatically uninstall the existing 
agent. This comparison is based on the server's FQDN. 
You must provide secure variables to this script as seen in the Required Variables section. 
Set these up in Nerdio Manager under Settings->Portal. The variables to create are:
    AutomateServerUrl
    AutomateServerToken or SystemPassword
#>

##### Secure Variables #####

$Server = 'automate.dtctoday.com'
$Token = 'f62d4d0e8d84c6f29e55b7b02ec17d62'
$Password = $null

##### Variables #####

#Set LocationID to install the Automate Agent directly to the appropieate client's location / site.
$LocationId = Read-Host "Enter location ID"


# Prompt the user for input on whether to install on one or many computers
$installOption = Read-Host "Do you want to install the application on one or many computers? (Type 1 for one, 2 for many)"

if ($installOption -eq "1") {
    # Install on one computer
    $computerName = Read-Host "Enter the name of the computer you want to install the application on"
    # Replace this with your actual application installation command
    # Example: Start-Process "setup.exe" -ArgumentList "/silent" -Wait
    Write-Host "Installing application on $computerName..."
} elseif ($installOption -eq "2") {
    # Install on many computers
    $searchOU = Read-Host "Enter the Active Directory OU path to search for computers"
    $computerNames = Get-ADComputer -SearchBase $searchOU -Filter * | Select-Object -ExpandProperty Name
    foreach ($computerName in $computerNames) {
        # Replace this with your actual application installation command
        # Example: Invoke-Command -ComputerName $computerName -ScriptBlock { Start-Process "setup.exe" -ArgumentList "/silent" -Wait }
        Write-Host "Installing application on $computerName..."
    }
} else {
    Write-Host "Invalid input. Please enter 1 or 2."
}




##### Script Logic #####

if(($Token -eq $null) -and  ($Password -eq $null)) {
Write-Output "ERROR: The secure variables AutomateServerToken or SystemPassword are not provided"
}

elseif ($Password) {
[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072); Invoke-Expression(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Get-Nerdio/NMM/main/scripted-actions/modules/CMSP_Automate-Module.psm1'); Install-Automate -Server $Server -LocationID $LocationId -SystemPassword $Password -Transcript
}

elseif ($Token) {
[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072); Invoke-Expression(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Get-Nerdio/NMM/main/scripted-actions/modules/CMSP_Automate-Module.psm1'); Install-Automate -Server $Server -LocationID $LocationId -Token $Token -Transcript
}
