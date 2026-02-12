# Vérifie si le script est exécuté en tant qu'administrateur
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    # Relance le script avec les droits administrateur
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Changer la polique d'exécution
Set-ExecutionPolicy RemoteSigned
Write-host Set-ExecutionPolicy RemoteSigned

function restau {
Checkpoint-Computer -Description "PointDeRestaurationDebloat" -RestorePointType "MODIFY_SETTINGS"
Write-Output "Point de restauration crée"
}

function Visual-Settings {
    
# Désactiver les effets visuels 
    Write-Output "Désactivation des effets visuels..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2

    $visualEffects = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $visualEffects -Name "TaskbarAnimations" -Value 0
    Set-ItemProperty -Path $visualEffects -Name "ListviewAlphaSelect" -Value 0
    Set-ItemProperty -Path $visualEffects -Name "ListviewShadow" -Value 0
    Set-ItemProperty -Path $visualEffects -Name "ListviewWatermark" -Value 0

  # Désactiver la zone de recherche de la barre des tâches
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0

# Utiliser des petites icônes dans la barre des tâches
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Value 1

# Combiner les boutons uniquement lorsque la barre des tâches est pleine
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value 2

# Supprimer Objets 3D
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force 
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force

# Afficher les extensions de fichiers pour les types de fichiers connus
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0

# Afficher les fichiers protégés du système d'exploitation
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1

# Afficher les fichiers et dossiers cachés
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1


# Redémarrer l'explorateur Windows pour appliquer les changements
Stop-Process -Name explorer -Force
Start-Process explorer

    Write-Output "Paramètres appliqués."
}

function Remove-PreinstalledApps {
       # Désinstaller les applications préinstallées
    Write-Output "Désinstallation des applications..."  
    $applications = @(
        "Microsoft.XboxApp",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.WindowsMaps",
        "Microsoft.ZuneMusic",#Groove Music
        "Microsoft.ZuneVideo", #Movies & TV
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.SkypeApp",
        "Microsoft.549981C3F5F10", # Cortana
        "Microsoft.MicrosoftSolitaireCollection",
        "Microsoft.MixedReality.Portal",
        "Microsoft.GetHelp",
        "Microsoft.Office.OneNote",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.Getstarted",# Astuces 
        "Microsoft.BingFinance",
        "Microsoft.BingNews",
        "Microsoft.BingSports",
        "Microsoft.3DBuilder"
            )

    foreach ($app in $applications) {
        Get-AppxPackage -AllUsers -Name $app | Remove-AppxPackage
    }

    # Supprimer les raccourcis du menu Démarrer
    $shortcuts = @(
        "*Spotify*",
        "*Twitter*",
        "*LinkedIn*",
        "Microsoft.Todos"
    )

    foreach ($shortcut in $shortcuts) {
        Get-AppxPackage -AllUsers -Name $shortcut | Remove-AppxPackage
    }

    # Redémarrer l'explorateur Windows pour appliquer les changements
    Stop-Process -Name explorer -Force
    Start-Process explorer

    Write-Output "applications désinstallées"


}

# Fonction pour désinstaller OneDrive
function Uninstall-OneDrive {
    Write-Output "Désinstallation de OneDrive..."
    Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue

    if (Test-Path "$env:SYSTEMROOT\System32\OneDriveSetup.exe") {
        Start-Process "$env:SYSTEMROOT\System32\OneDriveSetup.exe" "/uninstall" -NoNewWindow -Wait
    }

    if (Test-Path "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe") {
        Start-Process "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe" "/uninstall" -NoNewWindow -Wait
    }

    Remove-Item -Path "$env:USERPROFILE\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue

    Remove-Item -Path "HKCU:\Software\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Output "OneDrive a bien été désinstallé."
}

function appsinstall {
#Start-Process -FilePath $InstallerPath -ArgumentList "/S" -Wait #Remplacer ou definir $InstallerPath

# Installation du gestionnaire de paquets Chocolatey et installation des apps
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

choco install firefox vlc 7zip sumatrapdf -y
Write-Output "Applications installées"
}

Set-ExecutionPolicy Bypass -Scope Process -Force; `
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; `
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Diverses optimisations et paramètres
function Tweaks {
fsutil behavior set disablelastaccess 1 # Désactiver la mise à jour de la date de dernier accès 
fsutil behavior set disable8dot3 1  #Désactiver la création de noms courts 8.3 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord

# Empêcher le redémarrage forcé de Windows Update
# Définir AUOptions = 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AUOptions" -Value 0 -Type DWord
# Créer la clé AU si elle n'existe pas
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
# Définir NoAutoRebootWithLoggedOnUsers = 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord

# Désactiver les services liés à la télémétrie
Stop-Service -Name "DiagTrack" -Force
Set-Service -Name "DiagTrack" -StartupType Disabled

Stop-Service -Name "dmwappushsvc" -Force
Set-Service -Name "dmwappushsvc" -StartupType Disabled
    
}

function Photoviewver {
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
}


# Fonction pour nettoyage disque
function Start-CleanMgr {
    $cleanMgrPath = "$env:windir\System32\cleanmgr.exe"
    $arguments = "/D C /LOWDISK"
    Start-Process -FilePath $cleanMgrPath -ArgumentList $arguments -NoNewWindow -Wait
}
function CTT {
iwr -useb https://christitus.com/win | iex

}

# Fonction pour lancer Microsoft Activation Scripts 
function MAS {
irm https://get.activated.win | iex
#irm https://massgrave.dev/get | iex

}

function Bloatbox {
Invoke-WebRequest -Uri "https://github.com/builtbybel/bloatbox/releases/download/0.20.0/bloatbox.zip" -OutFile "$env:TEMP\bloatbox.zip"
Expand-Archive -Path "$env:TEMP\bloatbox.zip" -DestinationPath "$env:TEMP\bloatbox"
Start-Process -FilePath "$env:TEMP\bloatbox\bloatbox.exe"
}

Function WebExperiencePack {
Get-AppxPackage -AllUsers *WebExperience* | Remove-AppxPackage
}

Function DISM-SFC {
DISM /Online /Cleanup-Image /RestoreHealth
sfc /scannow
}
Function hosts {
Start-Process notepad.exe "$env:SystemRoot\System32\drivers\etc\hosts" -Verb RunAs
}
function Privacy-Settings {
    Write-Output "Désactivation de la télémétrie et autres options de tracking..."
    # Désactiver les publicités personnalisées
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
    # Désactiver l'identifiant unique publicitaire
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
    # Désactiver les recommandations de l'assistant vocal Cortana
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Value 0
    Write-Output "Paramètres de confidentialité ajustés."
}

# Fonction pour afficher le menu
function Show-Menu {
    Clear-Host
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "          MENU PARAMETRAGE WINDOWS       " -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "R. Créer un point de restauration" -ForegroundColor Magenta
    Write-Host "*************************************" -ForegroundColor Cyan
    Write-Host "1. Paramètres visuels : barre des taches + effets" -ForegroundColor Yellow
    Write-Host "2. Désinstaller Cortana et autres applications inutiles" -ForegroundColor Yellow
    Write-Host "3. Désinstaller Onedrive" -ForegroundColor Yellow
    Write-Host "4. "Installer Firefox, VLC, 7Zip et SumatraPDF -ForegroundColor Yellow
    Write-Host "5. Optimisations diverses" -ForegroundColor Yellow
    Write-Host "6. Restaurer la Visionneuse photos Windows 7 " -ForegroundColor Yellow
    Write-Host "7. Tout exécuter" -ForegroundColor DarkYellow
    Write-Host "*************************************" -ForegroundColor Cyan
    Write-Host "             DIVERS" -ForegroundColor Green
    Write-Host "8. Nettoyage de disque avancé" -ForegroundColor Yellow
    Write-Host "9. Chris Titus Tech's Windows Utility" -ForegroundColor Yellow
    Write-Host "10. Microsoft Activation Scripts (MAS)" -ForegroundColor Yellow
    Write-Host "11. Bloatbox : Supprimer les Bloatwares de Windows" -ForegroundColor Yellow
    Write-Host "12. Désinstaller Widgets et centres d'intérêts (Windows 11)" -ForegroundColor Yellow
    Write-Host "13. Fichier hosts" -ForegroundColor Yellow
    Write-Host "14. Modifier les paramètres de confidentialité" -ForegroundColor Yellow
    Write-Host "15. DISM SFC" -ForegroundColor Yellow
    Write-Host "=====================================" -ForegroundColor Cyan

        Write-Host "Q. Quitter" -ForegroundColor Red
}

# Fonction principale
function Main {
    do {
        Show-Menu
        $choice = Read-Host "Sélectionnez une option "
        switch ($choice) {
            R {
                Restau
                Read-Host "Appuyez sur Entrée pour continuer..."
            }
            1 {
                Visual-Settings
                Read-Host "Appuyez sur Entrée pour continuer..."
            }
            2 {
                Remove-PreinstalledApps
                Read-Host "Appuyez sur Entrée pour continuer..."
            }           
            3 {
                Uninstall-OneDrive
                Read-Host "Appuyez sur Entrée pour continuer..."
            }
            4 {
                appsinstall
                Read-Host "Appuyez sur Entrée pour continuer..."
            }
            5 {
                Tweaks
                Read-Host "Appuyez sur Entrée pour continuer..."
            }
            6 {
                Photoviewver
                Read-Host "Appuyez sur Entrée pour continuer..."
            }
            7 {
                Visual-Settings
                Remove-PreinstalledApps
                Uninstall-OneDrive
                Photoviewver
                Read-Host "Appuyez sur Entrée pour continuer..."
              }
            8 {
                Start-CleanMgr
                Read-Host "Appuyez sur Entrée pour continuer..."
            }
            9 {
                CTT
                Read-Host "Appuyez sur Entrée pour continuer..."
            }
            
            10 {
                MAS
                Read-Host "Appuyez sur Entrée pour continuer..."
            }
            11 {
                Bloatbox
                Read-Host "Appuyez sur Entrée pour continuer..."
            }
            12 {
                WebExperiencePack
                Read-Host "Appuyez sur Entrée pour continuer..."
            }
            13 {
                hosts
                Read-Host "Appuyez sur Entrée pour continuer..."
            }
  
            14 {
    Privacy-Settings
    Read-Host "Appuyez sur Entrée pour continuer..."
}
          15 {
                DISM-SFC
                Read-Host "Appuyez sur Entrée pour continuer..."
            }                       
            "Q" {
                Write-Host "Sortie du script... Au revoir !" -ForegroundColor Green
                Start-Sleep -Milliseconds 500 
                break
            }

         default {
                Write-Host "Choix invalide. Veuillez réessayer." -ForegroundColor Red
                
            }
        }
    } while ($choice -ne "Q") # "Q" étant le nouveau choix de quitter
}

# Exécution de la fonction principale
Main
