$ret = Test-Path C:\NEISPTL
if (-not $ret) {
    New-Item C:\NEISPTL -ItemType Directory -ErrorAction SilentlyContinue
}

Set-Location -Path C:\NEISPTL

Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading IEMode Setup File...";
Invoke-WebRequest -Uri http://neis.ice.go.kr/EP/htdocs/edge_guide/guide/IEMode_v1.5.zip -Outfile IEMode_v1.5.zip;
Expand-Archive IEMode_v1.5.zip -DestinationPath . -Force;

Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading nProtect Online Security Setup File...";
Invoke-WebRequest -Uri https://supdate.nprotect.net/nprotect/nos_service/windows/install/nos_setup.exe -Outfile nos_setup.exe;

Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading KCaseAgent Setup File...";
Invoke-WebRequest -Uri https://update.ksign.com/eis/evpn/KCaseAgent_Installer.exe -Outfile KCaseAgent_Installer.exe

Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading WeGuadia SSLplus Setup File...";
Invoke-WebRequest -Uri https://evpn.ice.go.kr/winsetup_evpn.ice.go.kr.exe -Outfile winsetup_evpn.ice.go.kr.exe

Write-Host -BackgroundColor Black -ForegroundColor Yellow "MS Edge의 환경설정을 진행합니다.";
$ret = Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Edge;
if (-not $ret) {
    [void](New-Item -Path HKLM:\Software\Policies\Microsoft\Edge);
}
[void](New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge -Name ExperimentationAndConfigurationServiceControl -PropertyType Dword -Value 0 -Force);

$ret = Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls;
if (-not $ret) {
    [void](New-Item -Path HKLM:\Software\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls);
}
[void](New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls -Name 1 -PropertyType String -Value "evpn.ice.go.kr" -Force);
[void](New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls -Name 2 -PropertyType String -Value "neis.ice.go.kr" -Force);
[void](New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls -Name 3 -PropertyType String -Value "klef.ice.go.kr" -Force);

Write-Host -BackgroundColor Black -ForegroundColor Yellow "IE모드 환경설정을 진행합니다.";
$ret = Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\ice.go.kr"
if ($ret) {
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\ice.go.kr";
}

$ret = Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\neis.go.kr"
if ($ret) {
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\neis.go.kr";
}
$ret = Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\klef.go.kr"
if ($ret) {
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\klef.go.kr";
}
[void](New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\ice.go.kr");
[void](New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\neis.go.kr");
[void](New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\klef.go.kr");

[void](New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\ice.go.kr" -Name "*" -PropertyType Dword -Value 2 -Force);
[void](New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\neis.go.kr" -Name "*" -PropertyType Dword -Value 2 -Force);
[void](New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\klef.go.kr" -Name "*" -PropertyType Dword -Value 2 -Force);

$ret = Test-Path "HKCU:\Software\Microsoft\Internet Explorer\BrowserEmulation\ClearableListData"
if ($ret) {
    Remove-Item -Path "HKCU:\Software\Microsoft\Internet Explorer\BrowserEmulation\ClearableListData";
}
$ret = Test-Path "HKCU\Software\Microsoft\Internet Explorer\Safety\ActiveXFiltering"
if ($ret) {
    Remove-Item -Path "HKCU\Software\Microsoft\Internet Explorer\Safety\ActiveXFiltering";
}
