@echo off

pushd %~dp0
::------------------------------------------------------------------------------
:: �����ڱ��� ���� Ȯ���ϰ� �����ڱ������� �����
cd /d "%~dp0" && ( if exist "%TEMP%\getadmin.vbs" del "%TEMP%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (cmd /u /c echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/k cd ""%~dp0"" && ""%~0"" %params%", "", "runas", 1 > "%TEMP%\getadmin.vbs" && "%TEMP%\getadmin.vbs" && exit /B )
::------------------------------------------------------------------------------
setlocal EnableExtensions EnableDelayedExpansion

title NEIS EVPN/PTL �缳�� ��ũ��Ʈ

PowerShell -nop -NoLogo -ExecutionPolicy bypass ./evpnsetup.ps1

popd