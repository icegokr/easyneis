$ret = Test-Path C:\NEISPTL
if (-not $ret) {
    New-Item C:\NEISPTL -ItemType Directory -ErrorAction SilentlyContinue
}

Set-Location -Path C:\NEISPTL

Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading IEMode Setup File...";
Invoke-WebRequest -Uri http://neis.ice.go.kr/EP/htdocs/edge_guide/guide/IEMode_v1.5.zip -Outfile IEMode_v1.5.zip;
Expand-Archive IEMode_v1.5.zip -DestinationPath .;

Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading nProtect Online Security Setup File...";
Invoke-WebRequest -Uri https://supdate.nprotect.net/nprotect/nos_service/windows/install/nos_setup.exe -Outfile nos_setup.exe;

Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading KCaseAgent Setup File...";
Invoke-WebRequest -Uri https://update.ksign.com/eis/evpn/KCaseAgent_Installer.exe -Outfile KCaseAgent_Installer.exe

Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading WeGuadia SSLplus Setup File...";
Invoke-WebRequest -Uri https://evpn.ice.go.kr/winsetup_evpn.ice.go.kr.exe -Outfile winsetup_evpn.ice.go.kr.exe

