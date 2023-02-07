<#
    설치에 필요한 작업용 폴더 생성
#>
$ret = Test-Path C:\NEISPTL
if (-not $ret) {
    [void](New-Item C:\NEISPTL -ItemType Directory -ErrorAction SilentlyContinue);
}

Set-Location -Path C:\NEISPTL

<#
    설치프로그램 다운로드
#>
Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading IEMode Setup File...";
Invoke-WebRequest -Uri https://evpn.ice.go.kr/view/common/page/IEMode_v1.5.zip -Outfile IEMode_v1.5.zip;
Expand-Archive IEMode_v1.5.zip -DestinationPath . -Force;

Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading nProtect Online Security Setup File...";
Invoke-WebRequest -Uri https://supdate.nprotect.net/nprotect/nos_service/windows/install/nos_setup.exe -Outfile nos_setup.exe;

Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading KCaseAgent Setup File...";
Invoke-WebRequest -Uri https://update.ksign.com/eis/evpn/KCaseAgent_Installer.exe -Outfile KCaseAgent_Installer.exe

Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading WeGuadia SSLplus Setup File...";
Invoke-WebRequest -Uri https://evpn.ice.go.kr/winsetup_evpn.ice.go.kr.exe -Outfile winsetup_evpn.ice.go.kr.exe

<#
    기존 프로그램 삭제
#>
# nProtect Online Security 삭제
"C:\Program Files (x86)\INCAInternet UnInstall\nProtect Online Security\nProtectUninstaller.exe"
# KCaseAgent CPP 삭제
"C:\Program Files (x86)\Ksign\KCase\Uninstall.exe"
# WeGuadia SSLplus 삭제
msiexec /i {65C996CA-5B6B-40A9-BE92-DD7E21B05418}

# SSLplus 서비스 종료 및 삭제
C:\Windows\System32\net.exe stop sslplusv2
C:\Windows\System32\sc.exe delete sslplusv2
C:\Windows\System32\net.exe stop sslplus
C:\Windows\System32\sc.exe delete sslplus

<#
    설치프로그램 시작
#>
./IEMode_v1.5.bat
./nos_setup.exe
./KCaseAgent_Installer.exe
./winsetup_evpn.ice.go.kr.exe
<#
    MS Edge용 레지스트리 설정 추가
#>
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
<#
    MS Internet Explore(IE 모드 포함)용 레지스트리 설정 추가
    신뢰할 수 있는 사이트 목록 추가(*ice.go.kr, *.neis.go.kr, *.klef.go.kr )
#>
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

# 호환성보기 설정 삭제
$ret = Test-Path "HKCU:\Software\Microsoft\Internet Explorer\BrowserEmulation\ClearableListData"
if ($ret) {
    Remove-Item -Path "HKCU:\Software\Microsoft\Internet Explorer\BrowserEmulation\ClearableListData";
}
# ActiveX 필터링 해제(도구 - ActiveX 필터링 메뉴 설정 관련)
$ret = Test-Path "HKCU\Software\Microsoft\Internet Explorer\Safety\ActiveXFiltering"
if ($ret) {
    Remove-Item -Path "HKCU\Software\Microsoft\Internet Explorer\Safety\ActiveXFiltering";
}

# 도구 - 인터넷옵션 설정 
# 일반 - 종료할 때 검색 기록 삭제
# 일반 - 설정 - 임시 인터넷 파일 - 저장된 페이지의 새 버전 확인(자동으로 -> 웹 페이지를 열 때마다 변경)
# 일반 - 설정 - 임시 인터넷 파일 - 사용할 디스크 공간(50 -> 330변경)
# 보안 - 신뢰할수 있는 사이트 - 사용자 지정 수준

# 팝업차단 해제
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\New Windows" -Name PopupMgr -PropertyType Dword -Value 0 -Force);
# Windows Defender SmartScreen 필터 해제
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\PhishingFilter" -Name EnabledV9 -PropertyType Dword -Value 0 -Force);
# TLS 모두 사용
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "SecureProtocols" -PropertyType Dword -Value 2688 -Force);
# 종료할때 검색기록삭제 체크 해제
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Privacy" -Name "ClearBrowsingHistoryOnExit" -PropertyType Dword -Value 0 -Force);
# 저장된 페이지의 새버전확인 -> 웹페이지를 열때마다
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "SyncMode5" -PropertyType Dword -Value 3 -Force);
# 사용할 디스크 공간 330MB로 설정
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache" -Name "ContentLimit" -PropertyType Dword -Value "0x14" -Force);
# 사용자 지정 수준 설정 등록
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "CurrentLevel" -PropertyType Dword -Value 0 -Force);
# Windows Defender SmartScreen 사용
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "2301" -PropertyType Dword -Value 3 -Force);
# 웹사이트에서 주소 또는 상태표시줄 없이 창을 열도록 허용
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "2104" -PropertyType Dword -Value 0 -Force);
# 크기 및 위치 제한 없이 스크립트 실행 창을 열 수 있습니다.
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "2102" -PropertyType Dword -Value 0 -Force);
# 팝업 차단 사용
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "1609" -PropertyType Dword -Value 0 -Force);
# 혼합된 콘텐츠 표시
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "1809" -PropertyType Dword -Value 3 -Force);
# XSS 필터 사용
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "1409" -PropertyType Dword -Value 3 -Force);
# 웹 사이트에서 스크립팅된 창을 사용하여 정보를 요청하도록 허용
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "2105" -PropertyType Dword -Value 0 -Force);
# 프로그램 클립보드 액세스 허용
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "1407" -PropertyType Dword -Value 0 -Force);
# 보호모드 사용 안함
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "2500" -PropertyType Dword -Value 3 -Force);