:: Windows Configuration Quick Scan
:: Update: 23-Nov-2024

echo off
cls
pushd %~dp0

echo Windows Configuration Quick Scan

For /f "tokens=2-4 delims=/ " %%a in ('date /t') do (set sysdate=%%c%%a%%b)
For /f "tokens=1 delims=\" %%a in ('hostname') do (set hostName=%%a)
set folder=%sysdate%_%hostName%
mkdir %folder%
cd %folder%

copy C:\Windows\System32\wbem\en-US\htable.xsl C:\Windows\system32\wbem /Y

echo [+] Collect User Accounts
wmic /output:acc_all.html useraccount get AccountType,Caption,Description,FullName,Disabled /format:htable

echo [+] Collect Windows Services 
wmic /output:service_all.html service get DisplayName,Description,PathName,State,StartName /format:htable
wmic /output:service_run.html service where state="Running" get DisplayName,Description,PathName,StartName /format:htable

echo [+] Collect a List of Installed Software 
wmic /output:software_all.html product get name,version,Installsource,InstallDate,InstallDate2,LocalPackage /format:htable

echo [+] Collect System Information
systeminfo > system.txt

echo [+] Collect a List of Hotfix
wmic /output:hotfix_all.html qfe list full /format:htable

echo [+] Collect System Security Settings
secedit /export /cfg cfg.ini

echo [+] Collect Windows Firewall Settings
netsh advfirewall show allprofiles > firewall.txt

echo [+] collect AutoPlay Policies
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" 2>nul | find /i "NoDriveTypeAutoRun" > autoplay.txt

del C:\Windows\system32\wbem\htable.xsl

echo [+] Reports are generated at %~dp0%report%
pause
