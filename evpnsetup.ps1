<#
    ��ġ�� �ʿ��� �۾��� ���� ����
#>
$ret = Test-Path C:\NEISPTL
if (-not $ret) {
    [void](New-Item C:\NEISPTL -ItemType Directory -ErrorAction SilentlyContinue);
}

Set-Location -Path C:\NEISPTL

<#
    ��ġ���α׷� �ٿ�ε�
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
    ���� ���α׷� ����
#>
# nProtect Online Security ����
"C:\Program Files (x86)\INCAInternet UnInstall\nProtect Online Security\nProtectUninstaller.exe"
# KCaseAgent CPP ����
"C:\Program Files (x86)\Ksign\KCase\Uninstall.exe"
# WeGuadia SSLplus ����
msiexec /i {65C996CA-5B6B-40A9-BE92-DD7E21B05418}

# SSLplus ���� ���� �� ����
C:\Windows\System32\net.exe stop sslplusv2
C:\Windows\System32\sc.exe delete sslplusv2
C:\Windows\System32\net.exe stop sslplus
C:\Windows\System32\sc.exe delete sslplus

<#
    ��ġ���α׷� ����
#>
./IEMode_v1.5.bat
./nos_setup.exe
./KCaseAgent_Installer.exe
./winsetup_evpn.ice.go.kr.exe
<#
    MS Edge�� ������Ʈ�� ���� �߰�
#>
Write-Host -BackgroundColor Black -ForegroundColor Yellow "MS Edge�� ȯ�漳���� �����մϴ�.";
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
    MS Internet Explore(IE ��� ����)�� ������Ʈ�� ���� �߰�
    �ŷ��� �� �ִ� ����Ʈ ��� �߰�(*ice.go.kr, *.neis.go.kr, *.klef.go.kr )
#>
Write-Host -BackgroundColor Black -ForegroundColor Yellow "IE��� ȯ�漳���� �����մϴ�.";
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

# ȣȯ������ ���� ����
$ret = Test-Path "HKCU:\Software\Microsoft\Internet Explorer\BrowserEmulation\ClearableListData"
if ($ret) {
    Remove-Item -Path "HKCU:\Software\Microsoft\Internet Explorer\BrowserEmulation\ClearableListData";
}
# ActiveX ���͸� ����(���� - ActiveX ���͸� �޴� ���� ����)
$ret = Test-Path "HKCU\Software\Microsoft\Internet Explorer\Safety\ActiveXFiltering"
if ($ret) {
    Remove-Item -Path "HKCU\Software\Microsoft\Internet Explorer\Safety\ActiveXFiltering";
}

# ���� - ���ͳݿɼ� ���� 
# �Ϲ� - ������ �� �˻� ��� ����
# �Ϲ� - ���� - �ӽ� ���ͳ� ���� - ����� �������� �� ���� Ȯ��(�ڵ����� -> �� �������� �� ������ ����)
# �Ϲ� - ���� - �ӽ� ���ͳ� ���� - ����� ��ũ ����(50 -> 330����)
# ���� - �ŷ��Ҽ� �ִ� ����Ʈ - ����� ���� ����

# �˾����� ����
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\New Windows" -Name PopupMgr -PropertyType Dword -Value 0 -Force);
# Windows Defender SmartScreen ���� ����
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\PhishingFilter" -Name EnabledV9 -PropertyType Dword -Value 0 -Force);
# TLS ��� ���
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "SecureProtocols" -PropertyType Dword -Value 2688 -Force);
# �����Ҷ� �˻���ϻ��� üũ ����
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Privacy" -Name "ClearBrowsingHistoryOnExit" -PropertyType Dword -Value 0 -Force);
# ����� �������� ������Ȯ�� -> ���������� ��������
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "SyncMode5" -PropertyType Dword -Value 3 -Force);
# ����� ��ũ ���� 330MB�� ����
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache" -Name "ContentLimit" -PropertyType Dword -Value "0x14" -Force);
# ����� ���� ���� ���� ���
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "CurrentLevel" -PropertyType Dword -Value 0 -Force);
# Windows Defender SmartScreen ���
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "2301" -PropertyType Dword -Value 3 -Force);
# ������Ʈ���� �ּ� �Ǵ� ����ǥ���� ���� â�� ������ ���
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "2104" -PropertyType Dword -Value 0 -Force);
# ũ�� �� ��ġ ���� ���� ��ũ��Ʈ ���� â�� �� �� �ֽ��ϴ�.
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "2102" -PropertyType Dword -Value 0 -Force);
# �˾� ���� ���
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "1609" -PropertyType Dword -Value 0 -Force);
# ȥ�յ� ������ ǥ��
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "1809" -PropertyType Dword -Value 3 -Force);
# XSS ���� ���
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "1409" -PropertyType Dword -Value 3 -Force);
# �� ����Ʈ���� ��ũ���õ� â�� ����Ͽ� ������ ��û�ϵ��� ���
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "2105" -PropertyType Dword -Value 0 -Force);
# ���α׷� Ŭ������ �׼��� ���
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "1407" -PropertyType Dword -Value 0 -Force);
# ��ȣ��� ��� ����
[void](New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" -Name "2500" -PropertyType Dword -Value 3 -Force);