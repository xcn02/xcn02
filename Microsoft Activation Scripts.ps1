# Vérifie si le script est exécuté en tant qu'administrateur
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    # Relance le script avec les droits administrateur
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
set-executionpolicy remotesigned
irm https://get.activated.win | iex
pause