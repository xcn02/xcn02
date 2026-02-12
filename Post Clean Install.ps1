# Vérifie si le script est lancé en admin, sinon relance en mode admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    $arguments = "& '" + $MyInvocation.MyCommand.Definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    break
}

Write-Host "Installez au préalable Windows depuis une clé USB ou après mise à niveau(autre script)"

Start-Sleep 1

Write-Host "`n---- 🔁 Conversion en Windows 10 IoT Enterprise LTSC 2021 ----`n"

# Installe la clé IoT LTSC
slmgr.vbs /ipk QPM6N-7J2WJ-P88HH-P3YRH-YY74H
Write-Host "✅ Terminée !" -ForegroundColor Green

Start-Sleep 1
Write-Host "`Activation avec Microsoft Activation Scripts (MAS)" -ForegroundColor Yellow
set-executionpolicy remotesigned
irm https://get.activated.win | iex

Write-Host "`Quelques paramètres" -ForegroundColor Yellow
# Reactiver la visionneuse Photos de Windows
New-Item -Path "HKLM:\Software\Classes\Applications\photoviewer.dll" -Force
New-Item -Path "HKLM:\Software\Classes\Applications\photoviewer.dll\shell" -Force
New-Item -Path "HKLM:\Software\Classes\Applications\photoviewer.dll\shell\open" -Force
New-Item -Path "HKLM:\Software\Classes\Applications\photoviewer.dll\shell\open\command" -Force
New-Item -Path "HKLM:\Software\Classes\Applications\photoviewer.dll\shell\open\DropTarget" -Force
New-Item -Path "HKLM:\Software\Classes\Applications\photoviewer.dll\shell\print" -Force
New-Item -Path "HKLM:\Software\Classes\Applications\photoviewer.dll\shell\print\command" -Force
New-Item -Path "HKLM:\Software\Classes\Applications\photoviewer.dll\shell\print\DropTarget" -Force
Set-ItemProperty -Path "HKLM:\Software\Classes\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Value "@photoviewer.dll,-3043"
$commandValueOpen = "$env:SystemRoot\System32\rundll32.exe `"$env:ProgramFiles\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
Set-ItemProperty -Path "HKLM:\Software\Classes\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Value $commandValueOpen
Set-ItemProperty -Path "HKLM:\Software\Classes\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
$commandValuePrint = "$env:SystemRoot\System32\rundll32.exe `"$env:ProgramFiles\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Print %1"
Set-ItemProperty -Path "HKLM:\Software\Classes\Applications\photoviewer.dll\shell\print\command" -Name "(Default)" -Value $commandValuePrint
Set-ItemProperty -Path "HKLM:\Software\Classes\Applications\photoviewer.dll\shell\print\DropTarget" -Name "Clsid" -Value "{60fd46de-f830-4894-a628-6fa81bc0190d}"

# Empêcher le redémarrage forcé de Windows Update
# Définir AUOptions = 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AUOptions" -Value 0 -Type DWord
# Créer la clé AU si elle n'existe pas
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
# Définir NoAutoRebootWithLoggedOnUsers = 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord