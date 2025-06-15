:: Windows Configuration Quick Scan
:: Last Update: 15-Jun-2025
:: Author: g4xyk00

echo off
cls
pushd %~dp0

echo Windows Configuration Quick Scan

For /f "tokens=2-4 delims=/ " %%a in ('date /t') do (set sysdate=%%c%%a%%b)
For /f "tokens=1 delims=\" %%a in ('hostname') do (set hostName=%%a)
set folder=%sysdate%_%hostName%_configs
mkdir %folder%
cd %folder%

copy C:\Windows\System32\wbem\en-US\htable.xsl C:\Windows\system32\wbem /Y

echo [+] Collect User Accounts
wmic /output:wmic_acc_all.html useraccount get AccountType,Caption,Description,FullName,Disabled /format:htable

echo [+] Collect Windows Services 
wmic /output:wmic_service_all.html service get DisplayName,Description,PathName,State,StartName /format:htable
wmic /output:wmic_service_run.html service where state="Running" get DisplayName,Description,PathName,StartName /format:htable
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" > reg_services.txt

echo [+] Collect Features listing for package
dism /online /Get-Features > dism_features.txt

echo [+] Collect a List of Installed Software 
wmic /output:wmic_software_all.html product get name,version,Installsource,InstallDate,InstallDate2,LocalPackage /format:htable

echo [+] Collect System Information
systeminfo > system.txt
w32tm /query /configuration > w32tm.txt

echo [+] Collect Network Information
wmic /output:wmic_nicconfig_all.html nicconfig get /format:htable
:: TcpipNetbiosOptions: 2 = Disable NetBIOS over TCP/IP
ipconfig /all > ipconfig.txt

echo [+] Collect a List of Hotfix
wmic /output:hotfix_all.html qfe list full /format:htable

echo [+] Collect System Security Settings
secedit /export /cfg cfg.ini

echo [+] Collect Windows Firewall Settings
netsh advfirewall show allprofiles > firewall.txt

echo [+] Collect AutoPlay Policies / Whitelist Application
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" > reg_explorer.txt

echo [+] Collect USB Port Status
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR" > reg_USBSTOR.txt
reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows" > reg_Windows.txt
reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\RemovableStorageDevices" > reg_Windows_RemovableStorageDevices.txt

echo [+] Collect SMB Signing Settings
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters" > reg_LanManWorkstation.txt
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" > reg_LanManServer.txt

echo [+] Collect Event Logs Settings
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security" > reg_event_security.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application" > reg_event_application.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System" > reg_event_system.txt

echo [+] Customised Items
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HarlequinLicenceServer" > reg_service_HarlequinLicenceServer.txt
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xLicenseService" > reg_service_xLicenseService.txt

del C:\Windows\system32\wbem\htable.xsl

echo [+] Reports are generated at %~dp0%report%
pause
