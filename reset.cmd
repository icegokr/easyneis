@echo off

::------------------------------------------------------------------------------
:: �����ڱ��� ���� Ȯ���ϰ� �����ڱ������� �����
cd /d "%~dp0" && ( if exist "%TEMP%\getadmin.vbs" del "%TEMP%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (cmd /u /c echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~dp0"" && ""%~0"" %params%", "", "runas", 1 > "%TEMP%\getadmin.vbs" && "%TEMP%\getadmin.vbs" && exit /B )
::------------------------------------------------------------------------------
setlocal EnableExtensions EnableDelayedExpansion

title NEIS EVPN/PTL �缳�� ��ũ��Ʈ

if not exist C:\NEISPTL (
    mkdir C:\NEISPTL
)

cd C:\NEISPTL

:: powershell -noprofile^
::     Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading IEMode Setup File...";^
::     Invoke-WebRequest -Uri http://neis.ice.go.kr/EP/htdocs/edge_guide/guide/IEMode_v1.5.zip -Outfile IEMode_v1.5.zip; ^
::     Expand-Archive IEMode_v1.5.zip -DestinationPath .;^
::     ^
::     Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading nProtect Online Security Setup File..."; ^
::     Invoke-WebRequest -Uri https://supdate.nprotect.net/nprotect/nos_service/windows/install/nos_setup.exe -Outfile nos_setup.exe; ^
::     ^
::     Write-Host -BackgroundColor Black -ForegroundColor Yellow "Downloading KCaseAgent Setup File..."; ^
::     Invoke-WebRequest -Uri https://update.ksign.com/eis/neisptl/KCaseAgent_Installer.exe -Outfile KCaseAgent_Installer.exe

::REM ���α׷� �缳ġ ����
::C:\NEISPTL\IEMode_v1.5.BAT
::C:\NEISPTL\nos_setup.exe
::C:\NEISPTL\KCaseAgent_Installer.exe

powershell -noprofile^
    Write-Host -BackgroundColor Black -ForegroundColor Yellow "MS Edge�� ȯ�漳���� �����մϴ�."; ^
    $ret = Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Edge;^
    if (-not $ret) { ^
        New-Item -Path HKLM:\Software\Policies\Microsoft\Edge; ^
    } ^
    [void](New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge -Name ExperimentationAndConfigurationServiceControl -PropertyType Dword -Value 0 -Force); ^
    ^
    $ret = Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls;^
    if (-not $ret) { ^
        New-Item -Path HKLM:\Software\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls;^
    } ^
    [void](New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls -Name 1 -PropertyType String -Value "evpn.ice.go.kr" -Force); ^
    [void](New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls -Name 2 -PropertyType String -Value "neis.ice.go.kr" -Force); ^
    [void](New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Edge\SleepingTabsBlockedForUrls -Name 3 -PropertyType String -Value "klef.ice.go.kr" -Force); ^

powershell -noprofile^
    Write-Host -BackgroundColor Black -ForegroundColor Yellow "IE��� ȯ�漳���� �����մϴ�."; ^


::REM �ŷ��Ҽ� �ִ� ����Ʈ�� ����ϱ�
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\ice.go.kr" /v "*" /t REG_DWORD /d 2 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\neis.go.kr" /v "*" /t REG_DWORD /d 2 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\klef.go.kr" /v "*" /t REG_DWORD /d 2 /f

::REM ȣȯ������ ���� ����
REG DELETE "HKCU\Software\Microsoft\Internet Explorer\BrowserEmulation\ClearableListData" /f

::REM ActiveX ���͸� ���� ����
REG DELETE "HKCU\Software\Microsoft\Internet Explorer\Safety\ActiveXFiltering" /f

echo �۾��� �Ϸ�Ǿ����ϴ�. �� â�� 10�� �Ŀ� �ڵ� ����˴ϴ�.