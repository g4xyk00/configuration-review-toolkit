:: SCGARY-CAT for Windows Server v1.2
:: Driver, 2008, 2008 R2 - Gary Kong (g4xyk00@gmail.com)
:: Win 2003 - Alex Wong
:: Date: 2015-08-11

echo off
cls

cd %~dp0

echo  \    /\       
echo   )  ( ')           
echo  (  /  )    SCGARY-CAT for Windows Server v1.2 ::
echo   \(__) ^|
@echo:

:: Make create evid folder
mkdir evid

:: OS Detection
echo Detecting OS...
systeminfo > evid/systeminfo.txt 
findstr /B /C:"OS Name" /C:"System Type" /C:"Host Name" "evid\systeminfo.txt"

:: Domain Role Detection
wmic computersystem get domainrole | findstr /v DomainRole > evid/domainrole.txt
set /p dr=<evid\domainrole.txt

IF NOT "%dr%" == "%dr:0=%" (
ECHO Domain Role:               Standalone workstation
)
IF NOT "%dr%" == "%dr:1=%" (
ECHO Domain Role:               Member workstation
)
IF NOT "%dr%" == "%dr:2=%" (
ECHO Domain Role:               Standalone server
)
IF NOT "%dr%" == "%dr:3=%" (
ECHO Domain Role:               Member server
)
IF NOT "%dr%" == "%dr:4=%" (
ECHO Domain Role:               Domain controller
)

@echo:

:: Select the profile automatically
for /f "tokens=* delims= " %%a in ('findstr /c:"OS Name:" "evid\systeminfo.txt"') do set "line=%%a"
SET M=0
SET CompOS=%OS%

IF NOT "%line%" == "%line:R2=%" (
SET M=3
SET CompOS=Windows Server 2008 R2
GOTO CONFIRM_OS
)
IF NOT "%line%" == "%line:2008=%" (
SET M=2
SET CompOS=Windows Server 2008
GOTO CONFIRM_OS
)
IF NOT "%line%" == "%line:2003=%" (
SET M=1
SET CompOS=Windows Server 2003
GOTO CONFIRM_OS
)
GOTO SELECT_OS

:CONFIRM_OS
SET /P T=Is your target machine %CompOS%^? (Y/N): 
IF %T%==Y GOTO COLLECT_GENERAL
IF %T%==y GOTO COLLECT_GENERAL
@echo:
:SELECT_OS
echo -- Profile --
echo [1] Windows Server 2003
echo [2] Windows Server 2008   
echo [3] Windows Server 2008 R2
echo [0] Exit Program

@echo:
:PROMPT
SET /P M=Please select correct profile and press ENTER: 
IF %M%==0 GOTO END
IF %M%==1 GOTO COLLECT_GENERAL
IF %M%==2 GOTO COLLECT_GENERAL
IF %M%==3 GOTO COLLECT_GENERAL
GOTO PROMPT


:COLLECT_GENERAL
:: Prompt user to type ideal filename
set /p filename=Specify Output Filename: 

:: Check for file name
IF [%filename%] == [] SET filename=result.txt
IF "%filename%" == "%filename:.txt=%" SET filename=%filename%.txt

:: START OF DATA EXTRACTION
echo Data Extraction...
IF %M%==1 GOTO COLLECT_2003

secedit /export /cfg evid/cfg.ini > nul
net user administrator > evid/netuseradmin.txt
auditpol.exe /get /category:* > evid/auditpol.txt
netsh advfirewall show allprofiles > evid/firewall.txt
net accounts > evid/netaccount.txt
gpresult /f /h evid/gporesult.html > nul
accesschk /accepteula -q -a * > evid/accesschk.txt

REG QUERY "HKLM\Software\Microsoft\Windows" > evid/registry.txt 2>nul
REG QUERY "HKLM\Software\Microsoft\Windows\CurrentVersion\Polices\Explorer\" >> evid/registry.txt 2>nul
REG QUERY "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" >> evid/registry.txt 2>nul
REG QUERY "HKLM\Software\Policies\Microsoft\Windows\Eventlog\Application" >> evid/registry.txt 2>nul
REG QUERY "HKLM\Software\Policies\Microsoft\Windows\Eventlog\Security" >> evid/registry.txt 2>nul
REG QUERY "HKLM\Software\Policies\Microsoft\Windows\Eventlog\System" >> evid/registry.txt 2>nul
REG QUERY "HKLM\Software\Policies\Microsoft\Windows\Installer" >> evid/registry.txt 2>nul
REG QUERY "HKLM\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers" >> evid/registry.txt 2>nul
REG QUERY "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" >> evid/registry.txt 2>nul
REG QUERY "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" >> evid/registry.txt 2>nul
REG QUERY "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Control\Lsa" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Control\Session" >> evid/registry.txt 2>nul
REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Services\LDAP" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" >> evid/registry.txt 2>nul
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" >> evid/registry.txt 2>nul
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:ScreenSaverGracePeriod" >> evid/registry.txt 2>nul
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" > evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Control\Session Manager" >> evid/registry.txt 2>nul
REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager:SafeDllSearchMode" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Control\Session Manager\Kernel" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" >> evid/registry.txt 2>nul
REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" >> evid/registry.txt 2>nul 
REG QUERY "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters:NullSessionShares" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters:DisableIPSourceRouting" >> evid/registry.txt 2>nul
REG QUERY "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters:DisableIPSourceRouting" >> evid/registry.txt 2>nul
GOTO COLLECT_END

::Collect Evidence files for Windows 2003
:COLLECT_2003
secedit /export /cfg evid/cfg.ini > nul
net accounts > evid/netaccount.txt

REG QUERY "HKEY_LOCAL_MACHINE\Software\Microsoft\Driver Signing" > evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\CrashControl" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\Application" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\Security" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\EventLog\System" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\IPSEC" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" >> evid/registry.txt 2>nul 
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netbt\Parameters" >> evid/registry.txt 2>nul
REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\RasMan\Parameters" >> evid/registry.txt 2>nul


:COLLECT_END
:: END OF DATA EXTRACTION
echo Evidence files are genarated in folder "evid".

:: START OF REPORT GENERATION
:: Generate Report based on the choice
IF %M%==1 GOTO 2003
IF %M%==2 GOTO 2008
IF %M%==3 GOTO 2008R2

::::::::::::::::::::::::::::::::::::::::::::::
:: Windows Server 2003
::::::::::::::::::::::::::::::::::::::::::::::
:2003
echo Generating report for Windows Server 2003...
echo --  Report for Windows Server 2003  -- > "%filename%"
:: 1.1.1.1.2 Account Lockout Policy
echo 1.1.1.1.2.1 Set 'Reset account lockout counter after' to '15' or more >> "%filename%"
net accounts | find "Lockout observation window (minutes)" >> "%filename%"

echo 1.1.1.1.2.2 Set 'Account lockout duration' to '15' or greater >> "%filename%"
net accounts | find "Lockout duration (minutes)" >> "%filename%"

echo 1.1.1.1.2.3 Set 'Account lockout threshold' is set to '6' or fewer >> "%filename%"
type evid\cfg.ini | find /i "LockoutBadCount"    >> "%filename%"

:: 1.1.1.1.3 Password Policy
echo 1.1.1.1.3.1 Set 'Maximum password age' to '60' or less >> "%filename%"
type evid\cfg.ini | find /i "MaximumPasswordAge" | find /v "MACHINE"    >> "%filename%"

echo 1.1.1.1.3.2 Set 'Enforce password history' to '24' or more >> "%filename%"
type evid\cfg.ini | find /i "PasswordHistorySize"    >> "%filename%"

echo 1.1.1.1.3.3 Set 'Store passwords using reversible encryption' to 'Disabled' >> "%filename%"
type evid\cfg.ini | find /i "ClearTextPassword"    >> "%filename%"

echo 1.1.1.1.3.4 Set 'Minimum password age' to '1' or more >> "%filename%"
type evid\cfg.ini | find /i "MinimumPasswordAge"    >> "%filename%"

echo 1.1.1.1.3.5 Set 'Password must meet complexity requirements' to 'Enabled' >> "%filename%"
type evid\cfg.ini | find /i "PasswordComplexity"    >> "%filename%"

echo 1.1.1.1.3.6 Set 'Minimum password length' to '14' or more >> "%filename%"
type evid\cfg.ini | find /i "MinimumPasswordLength"    >> "%filename%"

:: 1.1.1.2.1 Security Options
echo 1.1.1.2.1.2 Set 'Accounts: Guest account status' to 'Disabled' >> "%filename%"
type evid\cfg.ini | find /i "EnableGuestAccount" >> "%filename%"

echo 1.1.1.2.1.3 Set 'Accounts: Limit local account use of blank passwords to console logon only' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "LimitBlankPasswordUse" >> "%filename%"

echo 1.1.1.2.1.5 Set 'Accounts: Administrator account status' to 'Disabled' >> "%filename%"
net user administrator | find /i "Account active" >> "%filename%"

echo 1.1.1.2.1.6 Set 'System objects: Default owner for objects created by members of the Administrators group' to 'Object creator' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "nodefaultadminowner" >> "%filename%"

echo 1.1.1.2.1.7 Set 'Network access: Shares that can be accessed anonymously' to 'None' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "NullSessionShares" >> "%filename%"

echo 1.1.1.2.1.8 Set 'Interactive logon: Smart card removal behavior' to 'Lock Workstation' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "scremoveoption" >> "%filename%"

echo 1.1.1.2.1.9 Set 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' to 'Require message integrity,Require message confidentiality,Require NTLMv2 session security,Require 128-bit encryption' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" 2>nul | find /i "NTLMMinClientSec" >> "%filename%"

echo 1.1.1.2.1.10 Set 'Devices: Prevent users from installing printer drivers' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" 2>nul | find /i "AddPrinterDrivers" >> "%filename%"

echo 1.1.1.2.1.11 Set 'Devices: Unsigned driver installation behavior' to 'Warn but allow installation' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Driver Signing" 2>nul | find /i "Policy" >> "%filename%"

echo 1.1.1.2.1.12 Set 'Recovery console: Allow floppy copy and access to all drives and all folders' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" 2>nul | find /i "setcommand" >> "%filename%"

echo 1.1.1.2.1.13 Set 'MSS: (DisableSavePassword) Prevent the dial-up password from being saved (recommended)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" 2>nul | find /i "DisableSavePassword" >> "%filename%"

echo 1.1.1.2.1.14 Set 'Network access: Restrict anonymous access to Named Pipes and Shares' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "restrictnullsessaccess" >> "%filename%"

echo 1.1.1.2.1.15 Set 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' to '90' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security" 2>nul | find /i "WarningLevel" >> "%filename%"

echo 1.1.1.2.1.16 Set 'MSS: (SynAttackProtect) Syn attack protection level (protects against DoS)' to 'Connections time out sooner if a SYN attack is detected' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" 2>nul | find /i "SynAttackProtect" >> "%filename%"

echo 1.1.1.2.1.17 Set 'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers" 2>nul | find /i "AuthenticodeEnabled" >> "%filename%"

echo 1.1.1.2.1.18 Set 'MSS: (AutoShareServer) Enable Administrative Shares (recommended except for highly secure environments)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" 2>nul | find /i "AutoShareServer" >> "%filename%"

echo 1.1.1.2.1.19 Set 'Shutdown: Clear virtual memory pagefile' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management" 2>nul | find /i "ClearPageFileAtShutdown" >> "%filename%"

echo 1.1.1.2.1.20 Set 'Domain member: Disable machine account password changes' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "disablepasswordchange" >> "%filename%"

echo 1.1.1.2.1.21 Set 'Microsoft network server: Amount of idle time required before suspending session' to '15' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "autodisconnect" >> "%filename%"

echo 1.1.1.2.1.22 Set 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netbt\Parameters" 2>nul | find /i "NoNameReleaseOnDemand" >> "%filename%"

echo 1.1.1.2.1.24 Set 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' to '300000 or 5 minutes (recommended)' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" 2>nul | find /i "KeepAliveTime" >> "%filename%"

echo 1.1.1.2.1.25 Set 'Shutdown: Allow system to be shut down without having to log on' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "ShutdownWithoutLogon" >> "%filename%"

echo 1.1.1.2.1.26 Set 'Interactive logon: Do not display last user name' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "DontDisplayLastUserName" >> "%filename%"

echo 1.1.1.2.1.27 Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM "&amp;" NTLM' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "LmCompatibilityLevel" >> "%filename%"

echo 1.1.1.2.1.30 Set 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "AutoAdminLogon" >> "%filename%"

echo 1.1.1.2.1.31 Set 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' to 'Require message integrity,Require message confidentiality,Require NTLMv2 session security,Require 128-bit encryption' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" 2>nul | find /i "NTLMMinServerSec" >> "%filename%"

echo 1.1.1.2.1.32 Set 'System objects: Require case insensitivity for non-Windows subsystems' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel" 2>nul | find /i "ObCaseInsensitive" >> "%filename%"

echo 1.1.1.2.1.34 Set 'System settings: Optional subsystems' to '' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems" 2>nul | find /i "optional" >> "%filename%"

echo 1.1.1.2.1.35 Set 'Devices: Allowed to format and eject removable media' to 'Administrators' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "AllocateDASD" >> "%filename%"

echo 1.1.1.2.1.36 Set 'Microsoft network client: Digitally sign communications (always)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" 2>nul | find /i "RequireSecuritySignature" >> "%filename%"

echo 1.1.1.2.1.37 Set 'Interactive logon: Prompt user to change password before expiration' to '14' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "passwordexpirywarning" >> "%filename%"

echo 1.1.1.2.1.38 Set 'Domain member: Maximum machine account password age' to '30' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "maximumpasswordage" >> "%filename%"

echo 1.1.1.2.1.39 Set 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" 2>nul | find /i "SafeDllSearchMode" >> "%filename%"

echo 1.1.1.2.1.41 Set 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)' to '3' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" 2>nul | find /i "TcpMaxDataRetransmissions" >> "%filename%"

echo 1.1.1.2.1.42 Set 'Domain member: Digitally sign secure channel data (when possible)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "signsecurechannel" >> "%filename%"

echo 1.1.1.2.1.43 Set 'Domain member: Digitally encrypt secure channel data (when possible)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "sealsecurechannel" >> "%filename%"

echo 1.1.1.2.1.45 Set 'Microsoft network client: Send unencrypted password to third-party SMB servers' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" 2>nul | find /i "EnablePlainTextPassword" >> "%filename%"

echo 1.1.1.2.1.46 Set 'Interactive logon: Do not require CTRL+ALT+DEL' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "DisableCAD" >> "%filename%"

echo 1.1.1.2.1.49 Set 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' to '0' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "ScreenSaverGracePeriod" >> "%filename%"

echo 1.1.1.2.1.50 Set 'Microsoft network client: Digitally sign communications (if server agrees)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" 2>nul | find /i "EnableSecuritySignature" >> "%filename%"

echo 1.1.1.2.1.51 Set 'Domain member: Digitally encrypt or sign secure channel data (always)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "requiresignorseal" >> "%filename%"

echo 1.1.1.2.1.52 Set 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" 2>nul | find /i "ProtectionMode" >> "%filename%"

echo 1.1.1.2.1.53 Set 'Network security: Do not store LAN Manager hash value on next password change' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "NoLMHash" >> "%filename%"

echo 1.1.1.2.1.54 Set 'Network access: Remotely accessible registry paths and sub-paths' to 'System\CurrentControlSet\Control\Print\Printers System\CurrentControlSet\Services\Eventlog Software\Microsoft\OLAP Server Software\Microsoft\Windows NT\CurrentVersion\Print Sof >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" 2>nul | find /i "Machine" >> "%filename%"

echo 1.1.1.2.1.56 Set 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' to 'Highest protection, source routing is completely disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" 2>nul | find /i "DisableIPSourceRouting" >> "%filename%"

echo 1.1.1.2.1.57 Set 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" 2>nul | find /i "PerformRouterDiscovery" >> "%filename%"

echo 1.1.1.2.1.58 Set 'MSS: (TcpMaxConnectResponseRetransmissions) SYN-ACK retransmissions when a connection request is not acknowledged' to '3 "&amp;" 6 seconds, half-open connections dropped after 21 seconds' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" 2>nul | find /i "TcpMaxConnectResponseRetransmissions" >> "%filename%"

echo 1.1.1.2.1.59 Set 'Microsoft network server: Disconnect clients when logon hours expire' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "enableforcedlogoff" >> "%filename%"

echo 1.1.1.2.1.60 Set 'Network access: Let Everyone permissions apply to anonymous users' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "EveryoneIncludesAnonymous" >> "%filename%"

echo 1.1.1.2.1.61 Set 'Microsoft network server: Digitally sign communications (always)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "requiresecuritysignature" >> "%filename%"

echo 1.1.1.2.1.62 Set 'Network security: LDAP client signing requirements' to 'Negotiate signing' or better >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP" 2>nul | find /i "LDAPClientIntegrity" >> "%filename%"

echo 1.1.1.2.1.63 Set 'Devices: Allow undock without having to log on' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "undockwithoutlogon" >> "%filename%"

echo 1.1.1.2.1.64 Set 'Audit: Audit the access of global system objects' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "AuditBaseObjects" >> "%filename%"

echo 1.1.1.2.1.65 Set 'MSS: (AutoReboot) Allow Windows to automatically restart after a system crash (recommended except for highly secure environments)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl" 2>nul | find /i "AutoReboot" >> "%filename%"

echo 1.1.1.2.1.66 Set 'Interactive logon: Require smart card' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "scforceoption" >> "%filename%"

echo 1.1.1.2.1.68 Set 'Network access: Allow anonymous SID/Name translation' to 'Disabled' >> "%filename%"
type evid\cfg.ini | find /i "LSAAnonymousNameLookup" >> "%filename%"

echo 1.1.1.2.1.69 Set 'Domain member: Require strong (Windows 2000 or later) session key' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "requirestrongkey" >> "%filename%"

echo 1.1.1.2.1.70 Set 'Network access: Remotely accessible registry paths' to 'System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\Control\Server Applications Software\Microsoft\Windows NT\CurrentVersion' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" 2>nul | find /i "Machine" >> "%filename%"

echo 1.1.1.2.1.71 Set 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' to '0' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "cachedlogonscount" >> "%filename%"

echo 1.1.1.2.1.73 Set 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "RestrictAnonymous" | findstr /v "sam" >> "%filename%"

echo 1.1.1.2.1.74 Set 'Recovery console: Allow automatic administrative logon' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" 2>nul | find /i "securitylevel" >> "%filename%"

echo 1.1.1.2.1.75 Set 'Audit: Shut down system immediately if unable to log security audits' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "crashonauditfail" >> "%filename%"

echo 1.1.1.2.1.76 Set 'Microsoft network server: Digitally sign communications (if client agrees)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "enablesecuritysignature" >> "%filename%"

echo 1.1.1.2.1.77 Set 'Network access: Sharing and security model for local accounts' to 'Classic - local users authenticate as themselves' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "ForceGuest" >> "%filename%"

echo 1.1.1.2.1.78 Set 'Network access: Do not allow anonymous enumeration of SAM accounts' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "RestrictAnonymousSAM" >> "%filename%"

echo 1.1.1.2.1.79 Set 'Interactive logon: Require Domain Controller authentication to unlock workstation' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "ForceUnlockLogon" >> "%filename%"

echo 1.1.1.2.1.80 Set 'Network access: Do not allow storage of credentials or .NET Passports for network authentication' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "DisableDomainCreds" >> "%filename%"

echo 1.1.1.2.1.81 Set 'MSS: (EnableDeadGWDetect) Allow automatic detection of dead network gateways (could lead to DoS)' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" 2>nul | find /i "EnableDeadGWDetect" >> "%filename%"

echo 1.1.1.2.1.82 Set 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "FIPSAlgorithmPolicy" >> "%filename%"

echo 1.1.1.2.1.83 Set 'Audit: Audit the use of Backup and Restore privilege' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "fullprivilegeauditing" >> "%filename%"

echo 1.1.1.2.1.84 Set 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" 2>nul | find /i "EnableICMPRedirect" >> "%filename%"

echo 1.1.1.2.1.85 Set 'MSS: (NoDefaultExempt) Configure IPSec exemptions for various types of network traffic.' to 'Only ISAKMP is exempt (recommended for Windows Server 2003)' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\IPSEC" 2>nul | find /i "NoDefaultExempt" >> "%filename%"

:: 1.1.1.2.2 Audit Policy
echo 1.1.1.2.2.2 Set 'Audit account logon events' to 'Success, Failure' >> "%filename%"
type evid\cfg.ini | find /i "AuditAccountLogon"    >> "%filename%"

echo 1.1.1.2.2.3 Set 'Audit logon events' to 'Success, Failure' >> "%filename%"
type evid\cfg.ini | find /i "AuditLogonEvents"    >> "%filename%"

echo 1.1.1.2.2.4 Set 'Audit process tracking' to 'No Auditing' >> "%filename%"
type evid\cfg.ini | find /i "AuditProcessTracking"    >> "%filename%"

echo 1.1.1.2.2.5 Set 'Audit account management' to 'Success, Failure' >> "%filename%"
type evid\cfg.ini | find /i "AuditAccountManage"    >> "%filename%"

echo 1.1.1.2.2.6 Set 'Audit policy change' to 'Success' (minimum) or 'Success and Failure' >> "%filename%"
type evid\cfg.ini | find /i "AuditPolicyChange"    >> "%filename%"

echo 1.1.1.2.2.7 Set 'Audit system events' to 'Success' (minimum) or 'Success and Failure' >> "%filename%"
type evid\cfg.ini | find /i "AuditSystemEvents"    >> "%filename%"

echo 1.1.1.2.2.8 Set 'Audit privilege use' to 'Failure' (minimum) or 'Success and Failure' >> "%filename%"
type evid\cfg.ini | find /i "AuditPrivilegeUse"    >> "%filename%"

:: 1.1.1.2.3 User Rights Assignment
echo 1.1.1.2.3.2 Set 'Allow log on through Terminal Services' to 'Administrators, Remote desktop Users' >> "%filename%"
type evid\cfg.ini | find /i "SeRemoteInteractiveLogonRight"    >> "%filename%"

echo 1.1.1.2.3.3 Set 'Take ownership of files or other objects' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeTakeOwnershipPrivilege"    >> "%filename%"

echo 1.1.1.2.3.6 Set 'Remove computer from docking station' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeUndockPrivilege"    >> "%filename%"

echo 1.1.1.2.3.8 Set 'Debug programs' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeDebugPrivilege"    >> "%filename%"

echo 1.1.1.2.3.10 Set 'Adjust memory quotas for a process' to 'Administrators, LOCAL SERVICE, NETWORK SERVICE' >> "%filename%"
type evid\cfg.ini | find /i "SeIncreaseQuotaPrivilege"    >> "%filename%"

echo 1.1.1.2.3.12 Set 'Shut down the system' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeShutdownPrivilege"    >> "%filename%"

echo 1.1.1.2.3.14 Set 'Replace a process level token' to 'LOCAL SERVICE, NETWORK SERVICE' >> "%filename%"
type evid\cfg.ini | find /i "SeAssignPrimaryTokenPrivilege"    >> "%filename%"

echo 1.1.1.2.3.20 Set 'Profile system performance' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeSystemProfilePrivilege"    >> "%filename%"

echo 1.1.1.2.3.22 Set 'Profile single process' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeProfileSingleProcessPrivilege"    >> "%filename%"

echo 1.1.1.2.3.24 Set 'Create a pagefile' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeCreatePagefilePrivilege"    >> "%filename%"

echo 1.1.1.2.3.25 Set 'Deny log on as a batch job' to 'Guests' >> "%filename%"
type evid\cfg.ini | find /i "SeDenyBatchLogonRight"    >> "%filename%"

echo 1.1.1.2.3.26 Set 'Deny log on through Terminal Services' to 'Guests' >> "%filename%"
type evid\cfg.ini | find /i "SeDenyRemoteInteractiveLogonRight"    >> "%filename%"

echo 1.1.1.2.3.29 Set 'Log on as a service' to 'NETWORK SERVICE' >> "%filename%"
type evid\cfg.ini | find /i "SeServiceLogonRight"    >> "%filename%"

echo 1.1.1.2.3.30 Set 'Deny access to this computer from the network' to 'ANONYMOUS LOGON, Guests' >> "%filename%"
type evid\cfg.ini | find /i "SeDenyNetworkLogonRight"    >> "%filename%"

echo 1.1.1.2.3.33 Set 'Allow log on locally' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeInteractiveLogonRight"    >> "%filename%"

echo 1.1.1.2.3.37 Set 'Manage auditing and security log' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeSecurityPrivilege"    >> "%filename%"

echo 1.1.1.2.3.40 Set 'Modify firmware environment values' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeSystemEnvironmentPrivilege"    >> "%filename%"

:: 1.1.1.3 Event Log
echo 1.1.1.3.1 Set 'Retention method for system log' to 'Overwrites events as needed' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System" 2>nul | find /i "Retention" >> "%filename%"

echo 1.1.1.3.2 Set 'Maximum application log size' to '16384' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\Application" 2>nul | find /i "MaxSize" >> "%filename%"

echo 1.1.1.3.3 Set 'Retention method for security log' to 'Overwrites events as needed' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security" 2>nul | find /i "Retention" >> "%filename%"

echo 1.1.1.3.4 Set 'Maximum system log size' to '16384' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System" 2>nul | find /i "MaxSize" >> "%filename%"

echo 1.1.1.3.5 Set 'Maximum security log size' to '81920' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security" 2>nul | find /i "MaxSize" >> "%filename%"

echo 1.1.1.3.6 Set 'Retention method for application log' to 'Overwrites events as needed' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application" 2>nul | find /i "Retention" >> "%filename%"

:: 1.2.2.4 Remote Procedure Call
echo 1.2.2.4.2 Set 'Restrictions for Unauthenticated RPC clients' to 'Enabled:Authenticated' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc" 2>nul | find /i "RestrictRemoteClients" >> "%filename%"

:: 1.2.3.1 AutoPlay Policies
echo 1.2.3.1.1 Set 'Turn off Autoplay' to 'Enabled:All drives' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" 2>nul | find /i "NoDriveTypeAutoRun" >> "%filename%"

:: 1.2.3.7 Windows Installer
echo 1.2.3.7.1 Set 'Always install with elevated privileges' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" 2>nul | find /i "AlwaysInstallElevated" >> "%filename%"

echo Done. Report for Windows Server 2003 is generated in %filename%
GOTO END


::::::::::::::::::::::::::::::::::::::::::::::
:: Windows Server 2008 
::::::::::::::::::::::::::::::::::::::::::::::
:2008
echo Generating report for Windows Server 2008...
echo --  Report for Windows Server 2008  -- > "%filename%"
@echo: >> "%filename%"

:: 1.1.1.2.1 Security Options
echo 1.1.1.2.1.1 Set 'Microsoft network server: Disconnect clients when logon hours expire' to 'Enabled' >> "%filename%"
type evid\registry.txt | find /i "enableforcedlogoff" >> "%filename%"

echo 1.1.1.2.1.5 Set 'Accounts: Guest account status' to 'Disabled' >> "%filename%"
type evid\cfg.ini | find /i "EnableGuestAccount" >> "%filename%"
 
echo 1.1.1.2.1.6 Set 'Network access: Let Everyone permissions apply to anonymous users' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "EveryoneIncludesAnonymous" >> "%filename%"

echo 1.1.1.2.1.10 Set 'Accounts: Administrator account status' to 'Disabled' >> "%filename%"
net user administrator | find "Account active" >> "%filename%"

echo 1.1.1.2.1.11 Set 'Domain member: Maximum machine account password age' to '30' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "maximumpasswordage" >> "%filename%"

echo 1.1.1.2.1.14 Set 'Microsoft network client: Digitally sign communications (always)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" 2>nul | find /i "RequireSecuritySignature" >> "%filename%"

echo 1.1.1.2.1.16 Set 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' to '2' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "cachedlogonscount" >> "%filename%"

echo 1.1.1.2.1.17 Set 'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers" 2>nul | find /i "AuthenticodeEnabled" >> "%filename%"

echo 1.1.1.2.1.19 Set 'Network access: Named Pipes that can be accessed anonymously' to 'browser' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "NullSessionPipes" | findstr /v "AdjustedNullSessionPipes" >> "%filename%" 

echo 1.1.1.2.1.20 Set 'User Account Control: Only elevate executables that are signed and validated' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "ValidateAdminCodeSignatures" >> "%filename%"

echo 1.1.1.2.1.21 Set 'Network access: Do not allow anonymous enumeration of SAM accounts' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "RestrictAnonymousSAM" >> "%filename%"

echo 1.1.1.2.1.23 Set 'Devices: Allowed to format and eject removable media' to 'Administrators' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "AllocateDASD" >> "%filename%"

echo 1.1.1.2.1.24 Set 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' to '0' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "ScreenSaverGracePeriod" >> "%filename%"

echo 1.1.1.2.1.25 Set 'User Account Control: Virtualize file and registry write failures to per-user locations' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "EnableVirtualization" >> "%filename%"

echo 1.1.1.2.1.26 Set 'Shutdown: Allow system to be shut down without having to log on' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "ShutdownWithoutLogon" >> "%filename%"

echo 1.1.1.2.1.27 Set 'Network access: Shares that can be accessed anonymously' to '' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "NullSessionShares" >> "%filename%"

echo 1.1.1.2.1.28 Set 'Domain member: Disable machine account password changes' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "disablepasswordchange" >> "%filename%"

echo 1.1.1.2.1.29 Set 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "scenoapplylegacyauditpolicy" >> "%filename%"

echo 1.1.1.2.1.30 Set 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "RestrictAnonymous" | findstr /v "restrictanonymoussam" >> "%filename%"

echo 1.1.1.2.1.31 Set 'Microsoft network server: Amount of idle time required before suspending session' to '15' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "autodisconnect" >> "%filename%"

echo 1.1.1.2.1.32 Set 'Microsoft network client: Send unencrypted password to third-party SMB servers' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" 2>nul | find /i "EnablePlainTextPassword" >> "%filename%"

echo 1.1.1.2.1.33 Set 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)' to '3' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" 2>nul | find /i "TcpMaxDataRetransmissions" >> "%filename%"

echo 1.1.1.2.1.34 Set 'Recovery console: Allow automatic administrative logon' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" 2>nul | find /i "securitylevel" >> "%filename%"

echo 1.1.1.2.1.35 Set 'Interactive logon: Smart card removal behavior' to 'Lock Workstation' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "scremoveoption" >> "%filename%"

echo 1.1.1.2.1.37 Set 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "EnableUIADesktopToggle" >> "%filename%"

echo 1.1.1.2.1.39 Set 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' to 'Require NTLMv2 session security,Require 128-bit encryption' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" 2>nul | find /i "NTLMMinClientSec" >> "%filename%"

echo 1.1.1.2.1.40 Set 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "AutoAdminLogon" >> "%filename%"

echo 1.1.1.2.1.41 Set 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)' to '3' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters" 2>nul | find /i "TcpMaxDataRetransmissions" >> "%filename%"

echo 1.1.1.2.1.43 Set 'Domain member: Digitally sign secure channel data (when possible)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "signsecurechannel" >> "%filename%"

echo 1.1.1.2.1.44 Set 'Network access: Remotely accessible registry paths' to 'System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\Control\Server Applications Software\Microsoft\Windows NT\CurrentVersion' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" 2>nul | find /i "Machine" >> "%filename%"

echo 1.1.1.2.1.45 Set 'Devices: Prevent users from installing printer drivers' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" 2>nul | find /i "AddPrinterDrivers" >> "%filename%"

echo 1.1.1.2.1.46 Set 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "EnableSecureUIAPaths" >> "%filename%"

echo 1.1.1.2.1.47 Set 'User Account Control: Detect application installations and prompt for elevation' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "EnableInstallerDetection" >> "%filename%"

echo 1.1.1.2.1.48 Set 'Shutdown: Clear virtual memory pagefile' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management" 2>nul | find /i "ClearPageFileAtShutdown" >> "%filename%"

echo 1.1.1.2.1.49 Set 'Microsoft network client: Digitally sign communications (if server agrees)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" 2>nul | find /i "EnableSecuritySignature" >> "%filename%"

echo 1.1.1.2.1.50 Set 'Network access: Remotely accessible registry paths and sub-paths' to 'System\CurrentControlSet\Control\Print\Printers System\CurrentControlSet\Services\Eventlog Software\Microsoft\OLAP Server Software\Microsoft\Windows NT\CurrentVersion\Print Sof >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" 2>nul | find /i "Machine" >> "%filename%"

echo 1.1.1.2.1.52 Set 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' to 'Highest protection, source routing is completely disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters" 2>nul | find /i "DisableIPSourceRouting" >> "%filename%"

echo 1.1.1.2.1.53 Set 'Microsoft network server: Digitally sign communications (if client agrees)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "enablesecuritysignature" >> "%filename%"

echo 1.1.1.2.1.54 Set 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" 2>nul | find /i "Enabled" >> "%filename%"

echo 1.1.1.2.1.55 Set 'Interactive logon: Do not require CTRL+ALT+DEL' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "DisableCAD" >> "%filename%"

echo 1.1.1.2.1.58 Set 'Network security: LDAP client signing requirements' to 'Negotiate signing' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP" 2>nul | find /i "LDAPClientIntegrity" >> "%filename%"

echo 1.1.1.2.1.59 Set 'Network access: Sharing and security model for local accounts' to 'Classic - local users authenticate as themselves' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "ForceGuest" >> "%filename%"

echo 1.1.1.2.1.60 Set 'Network access: Allow anonymous SID/Name translation' to 'Disabled' >> "%filename%"
type evid\cfg.ini | find /i "LSAAnonymousNameLookup" >> "%filename%"

echo 1.1.1.2.1.61 Set 'Domain member: Digitally encrypt secure channel data (when possible)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "sealsecurechannel" >> "%filename%"

echo 1.1.1.2.1.62 Set 'User Account Control: Switch to the secure desktop when prompting for elevation' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "PromptOnSecureDesktop" >> "%filename%"

echo 1.1.1.2.1.63 Set 'Network access: Restrict anonymous access to Named Pipes and Shares' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "restrictnullsessaccess" >> "%filename%"

echo 1.1.1.2.1.64 Set 'Interactive logon: Prompt user to change password before expiration' to '14' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "passwordexpirywarning" >> "%filename%"

echo 1.1.1.2.1.65 Set 'Accounts: Limit local account use of blank passwords to console logon only' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "LimitBlankPasswordUse" >> "%filename%"

echo 1.1.1.2.1.66 Set 'User Account Control: Admin Approval Mode for the Built-in Administrator account' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "FilterAdministratorToken" >> "%filename%"

echo 1.1.1.2.1.67 Set 'System objects: Require case insensitivity for non-Windows subsystems' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel" 2>nul | find /i "ObCaseInsensitive" >> "%filename%"

echo 1.1.1.2.1.68 Set 'Audit: Shut down system immediately if unable to log security audits' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "crashonauditfail" >> "%filename%"

echo 1.1.1.2.1.69 Set 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' to 'Prompt for credentials' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "ConsentPromptBehaviorAdmin" >> "%filename%"

echo 1.1.1.2.1.70 Set 'Microsoft network server: Digitally sign communications (always)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "requiresecuritysignature" >> "%filename%"

echo 1.1.1.2.1.72 Set 'User Account Control: Run all administrators in Admin Approval Mode' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "EnableLUA" >> "%filename%"

echo 1.1.1.2.1.73 Set 'Interactive logon: Require Domain Controller authentication to unlock workstation' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "ForceUnlockLogon" >> "%filename%"

echo 1.1.1.2.1.74 Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM ^& NTLM' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "LmCompatibilityLevel" >> "%filename%"

echo 1.1.1.2.1.75 Set 'Domain member: Digitally encrypt or sign secure channel data (always)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "requiresignorseal" >> "%filename%"

echo 1.1.1.2.1.77 Set 'Interactive logon: Do not display last user name' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "DontDisplayLastUserName" >> "%filename%"

echo 1.1.1.2.1.78 Set 'Domain member: Require strong (Windows 2000 or later) session key' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "requirestrongkey" >> "%filename%"

echo 1.1.1.2.1.79 Set 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" 2>nul | find /i "ProtectionMode" >> "%filename%"

echo 1.1.1.2.1.80 Set 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' to 'Require NTLMv2 session security,Require 128-bit encryption' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" 2>nul | find /i "NTLMMinServerSec" >> "%filename%"

echo 1.1.1.2.1.81 Set 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' to '90' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security" 2>nul | find /i "WarningLevel" >> "%filename%"

echo 1.1.1.2.1.82 Set 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" 2>nul | find /i "SafeDllSearchMode" >> "%filename%"

echo 1.1.1.2.1.83 Set 'Recovery console: Allow floppy copy and access to all drives and all folders' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" 2>nul | find /i "setcommand" >> "%filename%"

echo 1.1.1.2.1.84 Set 'Network security: Do not store LAN Manager hash value on next password change' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "NoLMHash" >> "%filename%"

echo 1.1.1.2.1.85 Set 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' to 'Highest protection, source routing is completely disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" 2>nul | find /i "DisableIPSourceRouting" >> "%filename%"

:: 1.1.1.2.2 User Rights Assignment
echo 1.1.1.2.2.5 Set 'Bypass traverse checking' to 'Administrators, Authenticated Users, Backup Operators, Local Service, Network Service' >> "%filename%"
type evid\cfg.ini | find /i "SeChangeNotifyPrivilege" >> "%filename%"

echo 1.1.1.2.2.8 Set 'Access this computer from the network' to 'Administrators, Authenticated Users' >> "%filename%"
type evid\cfg.ini | find /i "SeNetworkLogonRight" >> "%filename%"

echo 1.1.1.2.2.9 Set 'Debug programs' to 'Administrators'  >> "%filename%"
type evid\cfg.ini | find /i "SeDebugPrivilege" >> "%filename%"

echo 1.1.1.2.2.11 Set 'Restore files and directories' to 'Administrators, Backup Operators' >> "%filename%"
type evid\cfg.ini | find /i "SeRestorePrivilege" >> "%filename%"

echo 1.1.1.2.2.15 Set 'Deny log on as a batch job' to 'Guests' >> "%filename%"
type evid\cfg.ini | find /i "SeDenyBatchLogonRight" >> "%filename%"

echo 1.1.1.2.2.17 Set 'Modify firmware environment values' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeSystemEnvironmentPrivilege" >> "%filename%"

echo 1.1.1.2.2.20 Set 'Replace a process level token' to 'LOCAL SERVICE, NETWORK SERVICE' >> "%filename%"
type evid\cfg.ini | find /i "SeAssignPrimaryTokenPrivilege" >> "%filename%"

:: NOTE: NEED TO BE TESTED!
echo 1.1.1.2.2.21 Set 'Allow log on through Terminal Services' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeRemoteInteractiveLogonRight" >> "%filename%"

echo 1.1.1.2.2.22 Set 'Generate security audits' to 'LOCAL SERVICE, NETWORK SERVICE' >> "%filename%"
type evid\cfg.ini | find /i "SeAuditPrivilege" >> "%filename%"

echo 1.1.1.2.2.23 Set 'Deny log on as a service' to 'No one' >> "%filename%"
type evid\cfg.ini | find /i "SeDenyServiceLogonRight" >> "%filename%"

echo 1.1.1.2.2.24 Set 'Force shutdown from a remote system' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeRemoteShutdownPrivilege" >> "%filename%"

echo 1.1.1.2.2.25 Set 'Adjust memory quotas for a process' to 'Administrators, LOCAL SERVICE, NETWORK SERVICE' >> "%filename%"
type evid\cfg.ini | find /i "SeIncreaseQuotaPrivilege" >> "%filename%"

echo 1.1.1.2.2.28 Set 'Change the time zone' to 'LOCAL SERVICE, Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeTimeZonePrivilege" >> "%filename%"

echo 1.1.1.2.2.30 Set 'Shut down the system' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeShutdownPrivilege" >> "%filename%"

echo 1.1.1.2.2.34 Set 'Take ownership of files or other objects' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeTakeOwnershipPrivilege" >> "%filename%"

:: NOTE: NEED TO BE TESTED!
echo 1.1.1.2.2.37 Set 'Deny log on through Terminal Services' to 'Guests' >> "%filename%"
type evid\cfg.ini | find /i "SeDenyRemoteInteractiveLogonRight" >> "%filename%"

echo 1.1.1.2.2.38 Set 'Deny access to this computer from the network' to 'Guests' >> "%filename%"
type evid\cfg.ini | find /i "SeDenyNetworkLogonRight" >> "%filename%"

echo 1.1.1.2.2.40 Set 'Remove computer from docking station' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeUndockPrivilege" >> "%filename%"

echo 1.1.1.2.2.41 Set 'Access Credential Manager as a trusted caller' to 'No One' >> "%filename%"
type evid\cfg.ini | find /i "SeTrustedCredManAccessPrivilege" >> "%filename%"

echo 1.1.1.2.2.42 Set 'Create a pagefile' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeCreatePagefilePrivilege" >> "%filename%"

echo 1.1.1.2.2.43 Set 'Deny log on locally' to 'Guests' >> "%filename%"
type evid\cfg.ini | find /i "SeDenyInteractiveLogonRight" >> "%filename%"

echo 1.1.1.2.2.44 Set 'Manage auditing and security log' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeSecurityPrivilege" >> "%filename%"

echo 1.1.1.2.2.45 Set 'Allow log on locally' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeInteractiveLogonRight" >> "%filename%"

echo 1.1.1.2.2.46 Set 'Profile single process' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeProfileSingleProcessPrivilege" >> "%filename%"

echo 1.1.1.2.2.47 Set 'Change the system time' to 'LOCAL SERVICE, Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeSystemtimePrivilege" >> "%filename%"

echo 1.1.1.2.2.48 Set 'Profile system performance' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeSystemProfilePrivilege" >> "%filename%"

echo 1.1.1.2.2.49 Set 'Act as part of the operating system' to 'No one' >> "%filename%"
type evid\cfg.ini | find /i "SeTcbPrivilege" >> "%filename%"


:: 1.1.1.3 Advanced Audit Policy Configuration
:: 1.1.1.3.1 Audit Policies
:: 1.1.1.3.1.1 Object Access
echo 1.1.1.3.1.1.1 Set 'Audit Policy: Object Access: Filtering Platform Packet Drop' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Filtering Platform Packet Drop" >> "%filename%"

echo 1.1.1.3.1.1.2 Set 'Audit Policy: Object Access: Handle Manipulation' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Handle Manipulation" >> "%filename%"

echo 1.1.1.3.1.1.3 Set 'Audit Policy: Object Access: Other Object Access Events' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Other Object Access Events" >> "%filename%"

echo 1.1.1.3.1.1.4 Set 'Audit Policy: Object Access: Kernel Object' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Kernel Object" >> "%filename%"

echo 1.1.1.3.1.1.5 Set 'Audit Policy: Object Access: Registry' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Registry" >> "%filename%"

echo 1.1.1.3.1.1.6 Set 'Audit Policy: Object Access: File System' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "File System" >> "%filename%"

echo 1.1.1.3.1.1.7 Set 'Audit Policy: Object Access: File Share' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "File Share" | findstr /v "Detailed" >> "%filename%"

echo 1.1.1.3.1.1.8 Set 'Audit Policy: Object Access: Filtering Platform Connection' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Filtering Platform Connection" >> "%filename%"

echo 1.1.1.3.1.1.9 Set 'Audit Policy: Object Access: Application Generated' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Application Generated" >> "%filename%"

echo 1.1.1.3.1.1.10 Set 'Audit Policy: Object Access: SAM' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "SAM" >> "%filename%"

echo 1.1.1.3.1.1.11 Set 'Audit Policy: Object Access: Certification Services' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Certification Services" >> "%filename%"

:: 1.1.1.3.1.2 Policy Change
echo 1.1.1.3.1.2.2 Set 'Audit Policy: Policy Change: Authorization Policy Change' to 'Success' >> "%filename%"
auditpol.exe /get /category:"Policy Change" | find /i "Authorization Policy Change" >> "%filename%"

echo 1.1.1.3.1.2.3 Set 'Audit Policy: Policy Change: Audit Policy Change' to 'Success and Failure' >> "%filename%"
auditpol.exe /get /category:"Policy Change" | find /i "Audit Policy Change" >> "%filename%"

echo 1.1.1.3.1.2.4 Set 'Audit Policy: Policy Change: MPSSVC Rule-Level Policy Change' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Policy Change" | find /i "MPSSVC Rule-Level Policy Change" >> "%filename%"

echo 1.1.1.3.1.2.5 Set 'Audit Policy: Policy Change: Other Policy Change Events' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Policy Change" | find /i "Other Policy Change Events" >> "%filename%"

echo 1.1.1.3.1.2.6 Set 'Audit Policy: Policy Change: Authentication Policy Change' to 'Success' >> "%filename%"
auditpol.exe /get /category:"Policy Change" | find /i "Authentication Policy Change" >> "%filename%"

echo 1.1.1.3.1.2.7 Set 'Audit Policy: Policy Change: Filtering Platform Policy Change' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Policy Change" | find /i "Filtering Platform Policy Change" >> "%filename%"

:: 1.1.1.3.1.3 System
echo 1.1.1.3.1.3.1 Set 'Audit Policy: System: System Integrity' to 'Success and Failure' >> "%filename%"
auditpol.exe /get /category:"System" | find /i "System Integrity" >> "%filename%"

echo 1.1.1.3.1.3.2 Set 'Audit Policy: System: Other System Events' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"System" | find /i "Other System Events" >> "%filename%"

echo 1.1.1.3.1.3.3 Set 'Audit Policy: System: IPsec Driver' to 'Success and Failure' >> "%filename%"
auditpol.exe /get /category:"System" | find /i "IPsec Driver" >> "%filename%"

echo 1.1.1.3.1.3.4 Set 'Audit Policy: System: Security State Change' to 'Success and Failure' >> "%filename%"
auditpol.exe /get /category:"System" | find /i "Security State Change" >> "%filename%"

echo 1.1.1.3.1.3.5 Set 'Audit Policy: System: Security System Extension' to 'Success and Failure' >> "%filename%"
auditpol.exe /get /category:"System" | find /i "Security System Extension" >> "%filename%"

:: 1.1.1.3.1.4 Detailed Tracking
echo 1.1.1.3.1.4.1 Set 'Audit Policy: Detailed Tracking: Process Creation' to 'Success' >> "%filename%"
auditpol.exe /get /category:"Detailed Tracking" | find /i "Process Creation" >> "%filename%"

echo 1.1.1.3.1.4.2 Set 'Audit Policy: Detailed Tracking: RPC Events' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Detailed Tracking" | find /i "RPC Events" >> "%filename%"

echo 1.1.1.3.1.4.3 Set 'Audit Policy: Detailed Tracking: Process Termination' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Detailed Tracking" | find /i "Process Termination" >> "%filename%"

echo 1.1.1.3.1.4.4 Set 'Audit Policy: Detailed Tracking: DPAPI Activity' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Detailed Tracking" | find /i "DPAPI Activity" >> "%filename%"

:: 1.1.1.3.1.5 Account Management
echo 1.1.1.3.1.5.1 Set 'Audit Policy: Account Management: Security Group Management' to 'Success and Failure' >> "%filename%"
auditpol.exe /get /category:"Account Management" | find /i "Security Group Management" >> "%filename%"

echo 1.1.1.3.1.5.2 Set 'Audit Policy: Account Management: User Account Management' to 'Success and Failure' >> "%filename%"
auditpol.exe /get /category:"Account Management" | find /i "User Account Management" >> "%filename%"

echo 1.1.1.3.1.5.3 Set 'Audit Policy: Account Management: Other Account Management Events' to 'Success and Failure' >> "%filename%"
auditpol.exe /get /category:"Account Management" | find /i "Other Account Management Events" >> "%filename%"

echo 1.1.1.3.1.5.4 Set 'Audit Policy: Account Management: Computer Account Management' to 'Success and Failure' >> "%filename%"
auditpol.exe /get /category:"Account Management" | find /i "Computer Account Management" >> "%filename%"

echo 1.1.1.3.1.5.5 Set 'Audit Policy: Account Management: Distribution Group Management' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Account Management" | find /i "Distribution Group Management" >> "%filename%"

echo 1.1.1.3.1.5.6 Set 'Audit Policy: Account Management: Application Group Management' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Account Management" | find /i "Application Group Management" >> "%filename%"

:: 1.1.1.3.1.6 DS Access
echo 1.1.1.3.1.6.2 Set 'Audit Policy: DS Access: Directory Service Changes' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"DS Access" | find /i "Directory Service Changes" >> "%filename%"

echo 1.1.1.3.1.6.3 Set 'Audit Policy: DS Access: Detailed Directory Service Replication' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"DS Access" | find /i "Detailed Directory Service Replication" >> "%filename%"

echo 1.1.1.3.1.6.5 Set 'Audit Policy: DS Access: Directory Service Access' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"DS Access" | find /i "Directory Service Access" >> "%filename%"

echo 1.1.1.3.1.6.6 Set 'Audit Policy: DS Access: Directory Service Replication' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"DS Access" | find /i "Directory Service Replication" | findstr /v "Detailed"  >> "%filename%"   

:: 1.1.1.3.1.7 Logon/Logoff
echo 1.1.1.3.1.7.2 Set 'Audit Policy: Logon-Logoff: Network Policy Server' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "Network Policy Server" >> "%filename%"

echo 1.1.1.3.1.7.3 Set 'Audit Policy: Logon-Logoff: Logon' to 'Success and Failure' >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "Logon" | findstr /v "Other Special /"  >> "%filename%"

echo 1.1.1.3.1.7.5 Set 'Audit Policy: Logon-Logoff: Other Logon/Logoff Events' to 'Success' >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "Other Logon/Logoff Events" >> "%filename%"

echo 1.1.1.3.1.7.6 Set 'Audit Policy: Logon-Logoff: IPsec Quick Mode' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "IPsec Quick Mode" >> "%filename%"

echo 1.1.1.3.1.7.8 Set 'Audit Policy: Logon-Logoff: Account Lockout' to 'Success' >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "Account Lockout" >> "%filename%"

echo 1.1.1.3.1.7.9 Set 'Audit Policy: Logon-Logoff: Special Logon' to 'Success' >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "Special Logon" >> "%filename%"

echo 1.1.1.3.1.7.10 Set 'Audit Policy: Logon-Logoff: Logoff' to 'Success' >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "Logoff" | findstr /v "Other /"  >> "%filename%"

echo 1.1.1.3.1.7.11 Set 'Audit Policy: Logon-Logoff: IPsec Extended Mode' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "IPsec Extended Mode" >> "%filename%"

echo 1.1.1.3.1.7.12 Set 'Audit Policy: Logon-Logoff: IPsec Main Mode' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "IPsec Main Mode" >> "%filename%"

:: 1.1.1.3.1.8 Privilege Use
echo 1.1.1.3.1.8.1 Set 'Audit Policy: Privilege Use: Sensitive Privilege Use' to 'Success and Failure' >> "%filename%"
auditpol.exe /get /category:"Privilege Use" | find /i "Sensitive Privilege Use" | findstr /v "Non"    >> "%filename%" 

echo 1.1.1.3.1.8.2 Set 'Audit Policy: Privilege Use: Non Sensitive Privilege Use' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Privilege Use" | find /i "Non Sensitive Privilege Use" >> "%filename%"

echo 1.1.1.3.1.8.3 Set 'Audit Policy: Privilege Use: Other Privilege Use Events' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Privilege Use" | find /i "Other Privilege Use Events" >> "%filename%"

:: 1.1.1.3.1.9 Account Logon
echo 1.1.1.3.1.9.2 Set 'Audit Policy: Account Logon: Credential Validation' to 'Success' >> "%filename%"
auditpol.exe /get /category:"Account Logon" | find /i "Credential Validation" >> "%filename%"

echo 1.1.1.3.1.9.3 Set 'Audit Policy: Account Logon: Other Account Logon Events' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Account Logon" | find /i "Other Account Logon Events" >> "%filename%"

echo 1.1.1.3.1.9.5 Set 'Audit Policy: Account Logon: Kerberos Authentication Service' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Account Logon" | find /i "Kerberos Authentication Service" >> "%filename%"

echo 1.1.1.3.1.9.7 Set 'Audit Policy: Account Logon: Kerberos Service Ticket Operations' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Account Logon" | find /i "Kerberos Service Ticket Operations" >> "%filename%"


:: 1.1.1.4 Windows Firewall with Advanced Security
:: 1.1.1.4.1 Windows Firewall with Advanced Security
:: 1.1.1.4.1.1 Windows Firewall Properties
:: 1.1.1.4.1.1.1 Private Profile
echo 1.1.1.4.1.1.1.1 Set 'Windows Firewall: Private: Firewall state' to 'On (recommended)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "EnableFirewall" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "State"  >> "%filename%"

echo 1.1.1.4.1.1.1.3 Set 'Windows Firewall: Private: Display a notification' to 'Yes (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "DisableNotifications" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "InboundUserNotification"  >> "%filename%" >> "%filename%"

echo 1.1.1.4.1.1.1.4 Set 'Windows Firewall: Private: Inbound connections' to 'Enabled:Block (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "DefaultInboundAction" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "Firewall Policy"  >> "%filename%" 

echo 1.1.1.4.1.1.1.6 Set 'Windows Firewall: Private: Apply local firewall rules' to 'Yes (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "AllowLocalPolicyMerge" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "LocalFirewallRules"  >> "%filename%"

echo 1.1.1.4.1.1.1.7 Set 'Windows Firewall: Private: Outbound connections' to 'Allow (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "DefaultOutboundAction" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "Firewall Policy"  >> "%filename%"

echo 1.1.1.4.1.1.1.9 Set 'Windows Firewall: Private: Apply local connection security rules' to 'Yes (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "AllowLocalIPsecPolicyMerge" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "LocalConSecRules"  >> "%filename%"

echo 1.1.1.4.1.1.1.11 Set 'Windows Firewall: Private: Allow unicast response' to 'No' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "DisableUnicastResponsesToMulticastBroadcast" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "UnicastResponseToMulticast"  >> "%filename%"

:: 1.1.1.4.1.1.2 Domain Profile
echo 1.1.1.4.1.1.2.1 Set 'Windows Firewall: Domain: Outbound connections' to 'Allow (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "DefaultOutboundAction" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "Firewall Policy"  >> "%filename%"

echo 1.1.1.4.1.1.2.3 Set 'Windows Firewall: Domain: Apply local firewall rules' to 'Yes (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "AllowLocalPolicyMerge" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "LocalFirewallRules"  >> "%filename%"

echo 1.1.1.4.1.1.2.4 Set 'Windows Firewall: Domain: Inbound connections' to 'Enabled:Block (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "DefaultInboundAction" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "Firewall Policy"  >> "%filename%"

echo 1.1.1.4.1.1.2.6 Set 'Windows Firewall: Domain: Display a notification' to 'Yes (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "DisableNotifications" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "InboundUserNotification"  >> "%filename%"

echo 1.1.1.4.1.1.2.7 Set 'Windows Firewall: Domain: Firewall state' to 'On (recommended)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "EnableFirewall" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "State"  >> "%filename%"

echo 1.1.1.4.1.1.2.9 Set 'Windows Firewall: Domain: Apply local connection security rules' to 'Yes (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "AllowLocalIPsecPolicyMerge" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "LocalConSecRules"  >> "%filename%"

echo 1.1.1.4.1.1.2.11 Set 'Windows Firewall: Domain: Allow unicast response' to 'No' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "DisableUnicastResponsesToMulticastBroadcast" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "UnicastResponseToMulticast"  >> "%filename%"

:: 1.1.1.4.1.1.3 Public Profile
echo 1.1.1.4.1.1.3.1 Set 'Windows Firewall: Public: Outbound connections' to 'Allow (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "DefaultOutboundAction" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "Firewall Policy"  >> "%filename%"

echo 1.1.1.4.1.1.3.3 Set 'Windows Firewall: Public: Apply local connection security rules' to 'Yes' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "AllowLocalIPsecPolicyMerge" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "LocalConSecRules"  >> "%filename%"

echo 1.1.1.4.1.1.3.4 Set 'Windows Firewall: Public: Inbound connections' to 'Enabled:Block (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "DefaultInboundAction" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "Firewall Policy"  >> "%filename%"

echo 1.1.1.4.1.1.3.6 Set 'Windows Firewall: Public: Allow unicast response' to 'No' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "DisableUnicastResponsesToMulticastBroadcast" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "UnicastResponseToMulticast"  >> "%filename%" 

echo 1.1.1.4.1.1.3.7 Set 'Windows Firewall: Public: Firewall state' to 'On (recommended)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "EnableFirewall" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "State"  >> "%filename%"

echo 1.1.1.4.1.1.3.9 Set 'Windows Firewall: Public: Display a notification' to 'Yes' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "DisableNotifications" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "InboundUserNotification"  >> "%filename%"

echo 1.1.1.4.1.1.3.11 Set 'Windows Firewall: Public: Apply local firewall rules' to 'Yes (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "AllowLocalPolicyMerge" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "LocalFirewallRules"  >> "%filename%"

:: 1.1.1.5 Account Policies
:: 1.1.1.5.1 Kerberos Policy
:: 1.1.1.5.2 Account Lockout Policy
echo 1.1.1.5.2.1 Set 'Account lockout duration' to '15' or greater >> "%filename%"
net accounts | find "Lockout duration (minutes)" >> "%filename%"

echo 1.1.1.5.2.2 Set 'Account lockout threshold' to '6' or fewer >> "%filename%"
type evid\cfg.ini | find /i "LockoutBadCount"    >> "%filename%"

:: 1.1.1.5.3 Password Policy
echo 1.1.1.5.3.2 Set 'Minimum password length' to '14' or greater >> "%filename%"
type evid\cfg.ini | find /i "MinimumPasswordLength"    >> "%filename%"

echo 1.1.1.5.3.3 Set 'Maximum password age' to '60' or less >> "%filename%"
type evid\cfg.ini | find /i "MaximumPasswordAge =" >> "%filename%"

echo 1.1.1.5.3.4 Set 'Enforce password history' to '24' or greater >> "%filename%"
type evid\cfg.ini | find /i "PasswordHistorySize"    >> "%filename%"

echo 1.1.1.5.3.5 Set 'Minimum password age' to '1' or greater >> "%filename%"
type evid\cfg.ini | find /i "MinimumPasswordAge"    >> "%filename%"

echo 1.1.1.5.3.6 Set 'Password must meet complexity requirements' to 'Enabled' >> "%filename%"
type evid\cfg.ini | find /i "PasswordComplexity"    >> "%filename%"

:: 1.2.2.1 Event Log Service
:: 1.2.2.1.1 System
echo 1.2.2.1.1.1 Set 'Maximum Log Size (KB)' to 'Enabled:32768' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Eventlog\System" 2>nul | find /i "maxSize"    >> "%filename%"

echo 1.2.2.1.1.2 Set 'Retain old events' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Eventlog\System" 2>nul |  find /i "retention" >> "%filename%"

:: 1.2.2.1.2 Application
echo 1.2.2.1.2.1 Set 'Maximum Log Size (KB)' to 'Enabled:32768' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Eventlog\Application" 2>nul | find /i "maxSize"    >> "%filename%"

echo 1.2.2.1.2.2 Set 'Retain old events' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Eventlog\Application" 2>nul | find /i "retention"    >> "%filename%"

:: 1.2.2.1.3 Security
echo 1.2.2.1.3.1 Set 'Retain old events' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Eventlog\Security" 2>nul | find /i "retention"    >> "%filename%"

echo 1.2.2.1.3.2 Set 'Maximum Log Size (KB)' to 'Enabled:196608' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Eventlog\Security" 2>nul | find /i "maxSize" >> "%filename%"

:: 1.2.2.4 AutoPlay Policies
echo 1.2.2.4.1 Set 'Turn off Autoplay' to 'Enabled:All drives' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Polices\Explorer\" 2>nul | find /i "NoDriveTypeAutoRun" >> "%filename%" 

:: 1.2.2.5 Windows Installer
echo 1.2.2.5.1 Set 'Always install with elevated privileges' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" 2>nul | find /i "AlwaysInstallElevated" >> "%filename%" 

echo Done. Report for Windows Server 2008 is generated in %filename%
GOTO END

::::::::::::::::::::::::::::::::::::::::::::::
:: Windows Server 2008 R2
::::::::::::::::::::::::::::::::::::::::::::::
:2008R2
echo Generating report for Windows Server 2008 R2...
echo --  Report for Windows Server 2008 R2  -- > "%filename%"
:: 1.1.1.2.1 Security Options
echo 1.1.1.2.1.5 Set 'Recovery console: Allow floppy copy and access to all drives and all folders' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" 2>nul | find /i "setcommand" >> "%filename%"

echo 1.1.1.2.1.9 Set 'Accounts: Guest account status' to 'Disabled' >> "%filename%"
type evid\cfg.ini | find /i "EnableGuestAccount" >> "%filename%"

echo 1.1.1.2.1.14 Set 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' to 'Prompt for consent for non-Windows binaries' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "ConsentPromptBehaviorAdmin" >> "%filename%"

echo 1.1.1.2.1.18 Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM ^& NTLM' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "LmCompatibilityLevel" >> "%filename%"

echo 1.1.1.2.1.22 Set 'User Account Control: Run all administrators in Admin Approval Mode' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "EnableLUA" >> "%filename%"

echo 1.1.1.2.1.26 Set 'User Account Control: Admin Approval Mode for the Built-in Administrator account' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "FilterAdministratorToken" >> "%filename%"

echo 1.1.1.2.1.29 Set 'Devices: Allowed to format and eject removable media' to 'Administrators and Interactive Users' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "AllocateDASD" >> "%filename%"

echo 1.1.1.2.1.30 Set 'System objects: Require case insensitivity for non-Windows subsystems' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel" 2>nul | find /i "ObCaseInsensitive" >> "%filename%"

echo 1.1.1.2.1.32 Set 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' to 'Highest protection, source routing is completely disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters:DisableIPSourceRouting" 2>nul >> "%filename%"

echo 1.1.1.2.1.34 Set 'Recovery console: Allow automatic administrative logon' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" 2>nul | find /i "securitylevel" >> "%filename%"

echo 1.1.1.2.1.40 Set 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' to '90' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\" 2>nul >> "%filename%"

echo 1.1.1.2.1.44 Set 'Domain member: Disable machine account password changes' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "disablepasswordchange" >> "%filename%"

echo 1.1.1.2.1.45 Set 'Domain member: Digitally encrypt secure channel data (when possible)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "sealsecurechannel" >> "%filename%"

echo 1.1.1.2.1.47 Set 'Network access: Allow anonymous SID/Name translation' to 'Disabled' >> "%filename%"
type evid\cfg.ini | find /i "LSAAnonymousNameLookup" >> "%filename%"

echo 1.1.1.2.1.49 Set 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" 2>nul | find /i "Enabled" >> "%filename%"

echo 1.1.1.2.1.51 Set 'Domain member: Digitally encrypt or sign secure channel data (always)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "requiresignorseal" >> "%filename%"

echo 1.1.1.2.1.52 Set 'Microsoft network server: Digitally sign communications (if client agrees)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "enablesecuritysignature" >> "%filename%"

echo 1.1.1.2.1.53 Set 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' to 'Require NTLMv2 session security,Require 128-bit encryption'  >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" 2>nul | find /i "NTLMMinServerSec" >> "%filename%"

echo 1.1.1.2.1.54 Set 'Network access: Sharing and security model for local accounts' to 'Classic - local users authenticate as themselves' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "ForceGuest" >> "%filename%"

echo 1.1.1.2.1.55 Set 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "EnableUIADesktopToggle" >> "%filename%"

echo 1.1.1.2.1.56 Set 'Accounts: Limit local account use of blank passwords to console logon only' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "LimitBlankPasswordUse" >> "%filename%"

echo 1.1.1.2.1.57 Set 'Microsoft network server: Digitally sign communications (always)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "requiresecuritysignature" >> "%filename%"

echo 1.1.1.2.1.60 Set 'Microsoft network server: Disconnect clients when logon hours expire' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "enableforcedlogoff" >> "%filename%"

echo 1.1.1.2.1.61 Set 'Domain member: Maximum machine account password age' to '30' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "maximumpasswordage" >> "%filename%"

echo 1.1.1.2.1.62 Set 'Network access: Restrict anonymous access to Named Pipes and Shares' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "restrictnullsessaccess" >> "%filename%"

echo 1.1.1.2.1.63 Set 'User Account Control: Switch to the secure desktop when prompting for elevation' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "PromptOnSecureDesktop" >> "%filename%"

echo 1.1.1.2.1.64 Set 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' to 'Highest protection, source routing is completely disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" 2>nul | find /i "DisableIPSourceRouting" >> "%filename%"

echo 1.1.1.2.1.65 Set 'Domain member: Digitally sign secure channel data (when possible)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "signsecurechannel" >> "%filename%"

echo 1.1.1.2.1.66 Set 'User Account Control: Only elevate executables that are signed and validated' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "ValidateAdminCodeSignatures" >> "%filename%"

echo 1.1.1.2.1.67 Set 'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers" 2>nul | find /i "AuthenticodeEnabled" >> "%filename%"

echo 1.1.1.2.1.69 Set 'Microsoft network client: Send unencrypted password to third-party SMB servers' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" 2>nul | find /i "EnablePlainTextPassword" >> "%filename%"

echo 1.1.1.2.1.71 Set 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" 2>nul | find /i "ProtectionMode" >> "%filename%"

echo 1.1.1.2.1.72 Set 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "RestrictAnonymous" | findstr /v "restrictanonymoussam" >> "%filename%"

echo 1.1.1.2.1.73 Set 'User Account Control: Virtualize file and registry write failures to per-user locations' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "EnableVirtualization" >> "%filename%"

echo 1.1.1.2.1.74 Set 'Interactive logon: Smart card removal behavior' to 'Lock Workstation' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "scremoveoption" >> "%filename%"

echo 1.1.1.2.1.75 Set 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' to '0' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "ScreenSaverGracePeriod" >> "%filename%"

echo 1.1.1.2.1.76 Set 'Interactive logon: Do not require CTRL+ALT+DEL' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "DisableCAD" >> "%filename%"

echo 1.1.1.2.1.78 Set 'Devices: Prevent users from installing printer drivers' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" 2>nul | find /i "AddPrinterDrivers" >> "%filename%"

echo 1.1.1.2.1.79 Set 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" 2>nul | find /i "SafeDllSearchMode" >> "%filename%"

echo 1.1.1.2.1.80 Set 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "AutoAdminLogon" >> "%filename%"

echo 1.1.1.2.1.81 Set 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' to 'Require NTLMv2 session security,Require 128-bit encryption' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" 2>nul | find /i "NTLMMinClientSec" >> "%filename%"

echo 1.1.1.2.1.82 Set 'Microsoft network client: Digitally sign communications (always)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" 2>nul | find /i "RequireSecuritySignature" >> "%filename%"

echo 1.1.1.2.1.83 Set 'Shutdown: Clear virtual memory pagefile' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management" 2>nul | find /i "ClearPageFileAtShutdown" >> "%filename%"

echo 1.1.1.2.1.84 Set 'Network access: Remotely accessible registry paths and sub-paths' to 'System\CurrentControlSet\Control\Print\Printers System\CurrentControlSet\Services\Eventlog Software\Microsoft\OLAP Server Software\Microsoft\Windows NT\CurrentVersion\Print Sof >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" 2>nul | find /i "Machine" >> "%filename%"

echo 1.1.1.2.1.85 Set 'Network access: Do not allow anonymous enumeration of SAM accounts' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "RestrictAnonymousSAM" >> "%filename%"

echo 1.1.1.2.1.86 Set 'Shutdown: Allow system to be shut down without having to log on' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "ShutdownWithoutLogon" >> "%filename%"

echo 1.1.1.2.1.87 Set 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "scenoapplylegacyauditpolicy" >> "%filename%"

echo 1.1.1.2.1.88 Set 'Network access: Let Everyone permissions apply to anonymous users' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "EveryoneIncludesAnonymous" >> "%filename%"

echo 1.1.1.2.1.90 Set 'User Account Control: Detect application installations and prompt for elevation' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "EnableInstallerDetection" >> "%filename%"

echo 1.1.1.2.1.91 Set 'Microsoft network client: Digitally sign communications (if server agrees)' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" 2>nul | find /i "EnableSecuritySignature" >> "%filename%"

echo 1.1.1.2.1.92 Set 'Network security: LDAP client signing requirements' to 'Negotiate signing' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP" 2>nul | find /i "LDAPClientIntegrity" >> "%filename%"

echo 1.1.1.2.1.93 Set 'Interactive logon: Do not display last user name' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "DontDisplayLastUserName" >> "%filename%"

echo 1.1.1.2.1.96 Set 'Network security: Do not store LAN Manager hash value on next password change' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "NoLMHash" >> "%filename%"

echo 1.1.1.2.1.97 Set 'Interactive logon: Prompt user to change password before expiration' to '14' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "passwordexpirywarning" >> "%filename%"

echo 1.1.1.2.1.100 Set 'Domain member: Require strong (Windows 2000 or later) session key' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters" 2>nul | find /i "requirestrongkey" >> "%filename%"

echo 1.1.1.2.1.101 Set 'Microsoft network server: Amount of idle time required before suspending session' to '15' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "autodisconnect" >> "%filename%"

echo 1.1.1.2.1.102 Set 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' to '0' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "cachedlogonscount" >> "%filename%"

echo 1.1.1.2.1.104 Set 'Interactive logon: Require Domain Controller authentication to unlock workstation' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | find /i "ForceUnlockLogon" >> "%filename%"

echo 1.1.1.2.1.107 Set 'User Account Control: Behavior of the elevation prompt for standard users' to 'Prompt for credentials' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "ConsentPromptBehaviorUser" >> "%filename%"

echo 1.1.1.2.1.109 Set 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' to 'Enabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" 2>nul | find /i "EnableSecureUIAPaths" >> "%filename%"

echo 1.1.1.2.1.110 Set 'Network access: Remotely accessible registry paths' to 'System\CurrentControlSet\Control\ProductOptions System\CurrentControlSet\Control\Server Applications Software\Microsoft\Windows NT\CurrentVersion' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" 2>nul | find /i "Machine" >> "%filename%"

echo 1.1.1.2.1.111 Set 'Audit: Shut down system immediately if unable to log security audits' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 2>nul | find /i "crashonauditfail" >> "%filename%"

echo 1.1.1.2.1.114 Set 'Network access: Shares that can be accessed anonymously' to '' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" 2>nul | find /i "NullSessionShares" >> "%filename%"

:: 1.1.1.2.2 User Right Assignment
echo 1.1.1.2.2.7 Set 'Generate security audits' to 'Local Service, Network Service' >> "%filename%"
type evid\cfg.ini | find /i "SeAuditPrivilege" >> "%filename%"

echo 1.1.1.2.2.10 Set 'Create a pagefile' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeCreatePagefilePrivilege"    >> "%filename%"

echo 1.1.1.2.2.13 Set 'Force shutdown from a remote system' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeRemoteShutdownPrivilege"    >> "%filename%"

echo 1.1.1.2.2.16 Set 'Allow log on through Remote Desktop Services' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeRemoteInteractiveLogonRight"    >> "%filename%"

echo 1.1.1.2.2.18 Set 'Enable computer and user accounts to be trusted for delegation' to 'No One' >> "%filename%"
type evid\cfg.ini | find /i "SeEnableDelegationPrivilege"    >> "%filename%"

echo 1.1.1.2.2.19 Set 'Lock pages in memory' to 'No One' >> "%filename%"
type evid\cfg.ini | find /i "SeLockMemoryPrivilege"    >> "%filename%"

echo 1.1.1.2.2.22 Set 'Deny access to this computer from the network' to 'Guests' >> "%filename%"
type evid\cfg.ini | find /i "SeDenyNetworkLogonRight"    >> "%filename%"

echo 1.1.1.2.2.24 Set 'Bypass traverse checking' to 'Administrators, Authenticated Users, Backup Operators, Local Service, Network Service' >> "%filename%"
type evid\cfg.ini | find /i "SeChangeNotifyPrivilege"    >> "%filename%"

echo 1.1.1.2.2.25 Set 'Debug programs' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeDebugPrivilege"    >> "%filename%"

echo 1.1.1.2.2.30 Set 'Deny log on as a batch job' to 'Guests' >> "%filename%"
type evid\cfg.ini | find /i "SeDenyBatchLogonRight"    >> "%filename%"

echo 1.1.1.2.2.33 Set 'Create global objects' to 'Administrators, SERVICE, LOCAL SERVICE, NETWORK SERVICE' >> "%filename%"
type evid\cfg.ini | find /i "SeCreateGlobalPrivilege"    >> "%filename%"

echo 1.1.1.2.2.35 Set 'Shut down the system' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeShutdownPrivilege"    >> "%filename%"

echo 1.1.1.2.2.38 Set 'Adjust memory quotas for a process' to 'Administrators, Local Service, Network Service' >> "%filename%"
type evid\cfg.ini | find /i "SeIncreaseQuotaPrivilege"    >> "%filename%"

echo 1.1.1.2.2.41 Set 'Access Credential Manager as a trusted caller' to 'No One' >> "%filename%"
type evid\cfg.ini | find /i "SeTrustedCredManAccessPrivilege"    >> "%filename%"

echo 1.1.1.2.2.44 Set 'Deny log on locally' to 'Guests' >> "%filename%"
type evid\cfg.ini | find /i "SeDenyInteractiveLogonRight"    >> "%filename%"

echo 1.1.1.2.2.47 Set 'Increase scheduling priority' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeIncreaseBasePriorityPrivilege"    >> "%filename%"

echo 1.1.1.2.2.50 Set 'Increase a process working set' to 'Administrators, Local Service' >> "%filename%"
type evid\cfg.ini | find /i "SeIncreaseWorkingSetPrivilege"    >> "%filename%"

echo 1.1.1.2.2.52 Set 'Access this computer from the network' to 'Administrators, Authenticated Users' >> "%filename%"
type evid\cfg.ini | find /i "SeNetworkLogonRight"    >> "%filename%"

echo 1.1.1.2.2.53 Set 'Act as part of the operating system' to 'No One' >> "%filename%"
type evid\cfg.ini | find /i "SeTcbPrivilege"    >> "%filename%"

echo 1.1.1.2.2.56 Set 'Impersonate a client after authentication' to 'Administrators, SERVICE, Local Service, Network Service' >> "%filename%"
type evid\cfg.ini | find /i "SeImpersonatePrivilege"    >> "%filename%"

echo 1.1.1.2.2.59 Set 'Manage auditing and security log' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeSecurityPrivilege"    >> "%filename%"

echo 1.1.1.2.2.61 Set 'Allow log on locally' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeInteractiveLogonRight"    >> "%filename%"

echo 1.1.1.2.2.63 Set 'Remove computer from docking station' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeUndockPrivilege"    >> "%filename%"

echo 1.1.1.2.2.64 Set 'Take ownership of files or other objects' to 'Administrators' >> "%filename%"
type evid\cfg.ini | find /i "SeTakeOwnershipPrivilege"    >> "%filename%"

:: 1.1.1.3 Advanced Audit Policy Configuration
:: 1.1.1.3.1 Audit Policies
:: 1.1.1.3.1.1 Object Access
echo 1.1.1.3.1.1.1 Set 'Audit Policy: Object Access: File System' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "File System" >> "%filename%"

echo 1.1.1.3.1.1.2 Set 'Audit Policy: Object Access: Handle Manipulation' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Handle Manipulation" >> "%filename%"

echo 1.1.1.3.1.1.3 Set 'Audit Policy: Object Access: Filtering Platform Packet Drop' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Filtering Platform Packet Drop" >> "%filename%"

echo 1.1.1.3.1.1.4 Set 'Audit Policy: Object Access: Certification Services' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Certification Services" >> "%filename%"

echo 1.1.1.3.1.1.5 Set 'Audit Policy: Object Access: SAM' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "SAM" >> "%filename%"

echo 1.1.1.3.1.1.6 Set 'Audit Policy: Object Access: Detailed File Share' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Detailed File Share" >> "%filename%"

echo 1.1.1.3.1.1.7 Set 'Audit Policy: Object Access: Registry' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Registry" >> "%filename%"

echo 1.1.1.3.1.1.8 Set 'Audit Policy: Object Access: Kernel Object' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Kernel Object" >> "%filename%"

echo 1.1.1.3.1.1.9 Set 'Audit Policy: Object Access: Filtering Platform Connection' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Filtering Platform Connection" >> "%filename%"

echo 1.1.1.3.1.1.10 Set 'Audit Policy: Object Access: File Share' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "File Share" | findstr /v "Detailed" >> "%filename%"

echo 1.1.1.3.1.1.11 Set 'Audit Policy: Object Access: Application Generated' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Application Generated" >> "%filename%"

echo 1.1.1.3.1.1.12 Set 'Audit Policy: Object Access: Other Object Access Events' to 'No Auditing' >> "%filename%"
auditpol.exe /get /category:"Object Access" | find /i "Other Object Access Events" >> "%filename%"

:: 1.1.1.3.1.2 Account Management
echo 1.1.1.3.1.2.2 Set 'Audit Policy: Account Management: Computer Account Management' to 'Success'   >> "%filename%"
auditpol.exe /get /category:"Account Management" | find /i "Computer Account Management"  >> "%filename%"

echo 1.1.1.3.1.2.3 Set 'Audit Policy: Account Management: Distribution Group Management' to 'No Auditing'   >> "%filename%"
auditpol.exe /get /category:"Account Management" | find /i "Distribution Group Management"  >> "%filename%"

echo 1.1.1.3.1.2.4 Set 'Audit Policy: Account Management: Security Group Management' to 'Success and Failure'  >> "%filename%"
auditpol.exe /get /category:"Account Management" | find /i "Security Group Management"  >> "%filename%"

echo 1.1.1.3.1.2.5 Set 'Audit Policy: Account Management: Application Group Management' to 'No Auditing'  >> "%filename%"
auditpol.exe /get /category:"Account Management" | find /i "Application Group Management"  >> "%filename%"

echo 1.1.1.3.1.2.6 Set 'Audit Policy: Account Management: Other Account Management Events' to 'Success and Failure'  >> "%filename%"
auditpol.exe /get /category:"Account Management" | find /i "Other Account Management Events"  >> "%filename%"

echo 1.1.1.3.1.2.7 Set 'Audit Policy: Account Management: User Account Management' to 'Success and Failure'  >> "%filename%"
auditpol.exe /get /category:"Account Management" | find /i "User Account Management"  >> "%filename%"

:: 1.1.1.3.1.3 DS Access
echo 1.1.1.3.1.3.2 Set 'Audit Policy: DS Access: Directory Service Access' to 'No Auditing'  >> "%filename%" 
auditpol.exe /get /category:"DS Access" | find /i "Directory Service Access"  >> "%filename%" 

echo 1.1.1.3.1.3.3 Set 'Audit Policy: DS Access: Directory Service Replication' to 'No Auditing'  >> "%filename%" 
auditpol.exe /get /category:"DS Access" | find /i "Directory Service Replication" | findstr /v "Detailed"  >> "%filename%"                    

echo 1.1.1.3.1.3.5 Set 'Audit Policy: DS Access: Directory Service Changes' to 'No Auditing' >> "%filename%" 
auditpol.exe /get /category:"DS Access" | find /i "Directory Service Changes" >> "%filename%" 

echo 1.1.1.3.1.3.6 Set 'Audit Policy: DS Access: Detailed Directory Service Replication' to 'No Auditing'   >> "%filename%" 
auditpol.exe /get /category:"DS Access" | find /i "Detailed Directory Service Replication" >> "%filename%" 

:: 1.1.1.3.1.4 Privilege Use
echo 1.1.1.3.1.4.1 Set 'Audit Policy: Privilege Use: Non Sensitive Privilege Use' to 'No Auditing'    >> "%filename%" 
auditpol.exe /get /category:"Privilege Use" | find /i "Non Sensitive Privilege Use"   >> "%filename%" 

echo 1.1.1.3.1.4.2 Set 'Audit Policy: Privilege Use: Other Privilege Use Events' to 'No Auditing'   >> "%filename%" 
auditpol.exe /get /category:"Privilege Use" | find /i "Other Privilege Use Events"    >> "%filename%" 

echo 1.1.1.3.1.4.3 Set 'Audit Policy: Privilege Use: Sensitive Privilege Use' to 'Success and Failure'   >> "%filename%" 
auditpol.exe /get /category:"Privilege Use" | find /i "Sensitive Privilege Use" | findstr /v "Non"    >> "%filename%" 

:: 1.1.1.3.1.5 Policy Change
echo 1.1.1.3.1.5.1 Set 'Audit Policy: Policy Change: Filtering Platform Policy Change' to 'No Auditing'   >> "%filename%" 
auditpol.exe /get /category:"Policy Change" | find /i "Filtering Platform Policy Change"   >> "%filename%"

echo 1.1.1.3.1.5.2 Set 'Audit Policy: Policy Change: Audit Policy Change' to 'Success and Failure'   >> "%filename%"
auditpol.exe /get /category:"Policy Change" | find /i "Audit Policy Change"   >> "%filename%"

echo 1.1.1.3.1.5.3 Set 'Audit Policy: Policy Change: Other Policy Change Events' to 'No Auditing'   >> "%filename%"
auditpol.exe /get /category:"Policy Change" | find /i "Other Policy Change Events"   >> "%filename%"

echo 1.1.1.3.1.5.4 Set 'Audit Policy: Policy Change: Authentication Policy Change' to 'Success'   >> "%filename%"
auditpol.exe /get /category:"Policy Change" | find /i "Authentication Policy Change"   >> "%filename%"

echo 1.1.1.3.1.5.5 Set 'Audit Policy: Policy Change: Authorization Policy Change' to 'No Auditing'   >> "%filename%"
auditpol.exe /get /category:"Policy Change" | find /i "Authorization Policy Change"   >> "%filename%"

echo 1.1.1.3.1.5.6 Set 'Audit Policy: Policy Change: MPSSVC Rule-Level Policy Change' to 'No Auditing'   >> "%filename%"
auditpol.exe /get /category:"Policy Change" | find /i "MPSSVC Rule-Level Policy Change"   >> "%filename%"

:: 1.1.1.3.1.6 System
echo 1.1.1.3.1.6.1 Set 'Audit Policy: System: IPsec Driver' to 'Success and Failure'  >> "%filename%"
auditpol.exe /get /category:"System" | find /i "IPsec Driver"  >> "%filename%"

echo 1.1.1.3.1.6.2 Set 'Audit Policy: System: Security State Change' to 'Success and Failure'  >> "%filename%"
auditpol.exe /get /category:"System" | find /i "Security State Change"  >> "%filename%"

echo 1.1.1.3.1.6.3 Set 'Audit Policy: System: Security System Extension' to 'Success and Failure'  >> "%filename%"
auditpol.exe /get /category:"System" | find /i "Security System Extension"  >> "%filename%"

echo 1.1.1.3.1.6.4 Set 'Audit Policy: System: Other System Events' to 'No Auditing'  >> "%filename%"
auditpol.exe /get /category:"System" | find /i "Other System Events"  >> "%filename%"

echo 1.1.1.3.1.6.5 Set 'Audit Policy: System: System Integrity' to 'Success and Failure'  >> "%filename%"
auditpol.exe /get /category:"System" | find /i "System Integrity"  >> "%filename%"

:: 1.1.1.3.1.7 Logon/Logoff
echo 1.1.1.3.1.7.1 Set 'Audit Policy: Logon-Logoff: IPsec Extended Mode' to 'No Auditing'  >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "IPsec Extended Mode"  >> "%filename%"

echo 1.1.1.3.1.7.2 Set 'Audit Policy: Logon-Logoff: Network Policy Server' to 'No Auditing'  >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "Network Policy Server"  >> "%filename%"

echo 1.1.1.3.1.7.3 Set 'Audit Policy: Logon-Logoff: IPsec Main Mode' to 'No Auditing'  >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "IPsec Main Mode"  >> "%filename%"

echo 1.1.1.3.1.7.4 Set 'Audit Policy: Logon-Logoff: Logoff' to 'Success'  >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "Logoff" | findstr /v "Other"  >> "%filename%"

echo 1.1.1.3.1.7.5 Set 'Audit Policy: Logon-Logoff: Other Logon/Logoff Events' to 'No Auditing'  >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "Other Logon/Logoff Events"  >> "%filename%"

echo 1.1.1.3.1.7.6 Set 'Audit Policy: Logon-Logoff: Special Logon' to 'Success'  >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "Special Logon"  >> "%filename%"

echo 1.1.1.3.1.7.7 Set 'Audit Policy: Logon-Logoff: Logon' to 'Success and Failure'  >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "Logon" | findstr /v "Other Special /"  >> "%filename%"

echo 1.1.1.3.1.7.8 Set 'Audit Policy: Logon-Logoff: Account Lockout' to 'No Auditing'  >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "Account Lockout"  >> "%filename%"

echo 1.1.1.3.1.7.9 Set 'Audit Policy: Logon-Logoff: IPsec Quick Mode' to 'No Auditing'  >> "%filename%"
auditpol.exe /get /category:"Logon/Logoff" | find /i "IPsec Quick Mode"  >> "%filename%"

:: 1.1.1.3.1.8 Account Logon
echo 1.1.1.3.1.8.1 Set 'Audit Policy: Account Logon: Kerberos Service Ticket Operations' to 'No Auditing'  >> "%filename%"
auditpol.exe /get /category:"Account Logon" | find /i "Kerberos Service Ticket Operations"  >> "%filename%"

echo 1.1.1.3.1.8.2 Set 'Audit Policy: Account Logon: Other Account Logon Events' to 'No Auditing'  >> "%filename%"
auditpol.exe /get /category:"Account Logon" | find /i "Other Account Logon Events"  >> "%filename%"

echo 1.1.1.3.1.8.3 Set 'Audit Policy: Account Logon: Credential Validation' to 'Success and Failure'  >> "%filename%"
auditpol.exe /get /category:"Account Logon" | find /i "Credential Validation"  >> "%filename%"

echo 1.1.1.3.1.8.4 Set 'Audit Policy: Account Logon: Kerberos Authentication Service' to 'No Auditing'  >> "%filename%"
auditpol.exe /get /category:"Account Logon" | find /i "Kerberos Authentication Service"  >> "%filename%"

:: 1.1.1.3.1.9 Detailed Tracking
echo 1.1.1.3.1.9.1 Set 'Audit Policy: Detailed Tracking: Process Termination' to 'No Auditing'  >> "%filename%"
auditpol.exe /get /category:"Detailed Tracking" | find /i "Process Termination"  >> "%filename%"

echo 1.1.1.3.1.9.2 Set 'Audit Policy: Detailed Tracking: RPC Events' to 'No Auditing'  >> "%filename%"
auditpol.exe /get /category:"Detailed Tracking" | find /i "RPC Events"  >> "%filename%"

echo 1.1.1.3.1.9.3 Set 'Audit Policy: Detailed Tracking: Process Creation' to 'Success'  >> "%filename%"
auditpol.exe /get /category:"Detailed Tracking" | find /i "Process Creation"   >> "%filename%"

echo 1.1.1.3.1.9.4 Set 'Audit Policy: Detailed Tracking: DPAPI Activity' to 'No Auditing'   >> "%filename%"
auditpol.exe /get /category:"Detailed Tracking" | find /i "DPAPI Activity"   >> "%filename%"

:: 1.1.1.4.1 Windows Firewall with Advanced Security
:: 1.1.1.4.1.1 Windows Firewall Properties
:: 1.1.1.4.1.1.1 Domain Profile
echo 1.1.1.4.1.1.1.1 Set 'Windows Firewall: Domain: Display a notification' to 'Yes (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "DisableNotifications" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "InboundUserNotification"  >> "%filename%"

echo 1.1.1.4.1.1.1.2 Set 'Windows Firewall: Domain: Apply local connection security rules' to 'Yes (default)'  >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "AllowLocalIPsecPolicyMerge" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "LocalConSecRules"  >> "%filename%"

echo 1.1.1.4.1.1.1.3 Set 'Windows Firewall: Domain: Allow unicast response' to 'No'  >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "DisableUnicastResponsesToMulticastBroadcast" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "UnicastResponseToMulticast"  >> "%filename%"

echo 1.1.1.4.1.1.1.4 Set 'Windows Firewall: Domain: Outbound connections' to 'Allow (default)'  >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "DefaultOutboundAction" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "Firewall Policy"  >> "%filename%"

echo 1.1.1.4.1.1.1.5 Set 'Windows Firewall: Domain: Apply local firewall rules' to 'Yes (default)'  >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "AllowLocalPolicyMerge" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "LocalFirewallRules"  >> "%filename%"

echo 1.1.1.4.1.1.1.6 Set 'Windows Firewall: Domain: Inbound connections' to 'Enabled:Block (default)'  >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "DefaultInboundAction" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "Firewall Policy"  >> "%filename%"

echo 1.1.1.4.1.1.1.7 Set 'Windows Firewall: Domain: Firewall state' to 'On (recommended)'  >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile 2>nul | find /i "EnableFirewall" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show domainprofile | find /i "State"  >> "%filename%"

:: 1.1.1.4.1.1.2 Private Profile
echo 1.1.1.4.1.1.2.1 Set 'Windows Firewall: Private: Outbound connections' to 'Allow (default)'   >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "DefaultOutboundAction" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "Firewall Policy"  >> "%filename%"

echo 1.1.1.4.1.1.2.2 Set 'Windows Firewall: Private: Apply local firewall rules' to 'Yes (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "AllowLocalPolicyMerge" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "LocalFirewallRules"  >> "%filename%"

echo 1.1.1.4.1.1.2.3 Set 'Windows Firewall: Private: Allow unicast response' to 'No' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "DisableUnicastResponsesToMulticastBroadcast" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "UnicastResponseToMulticast"  >> "%filename%"

echo 1.1.1.4.1.1.2.4 Set 'Windows Firewall: Private: Inbound connections' to 'Enabled:Block (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "DefaultInboundAction" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "Firewall Policy"  >> "%filename%" 

echo 1.1.1.4.1.1.2.5 Set 'Windows Firewall: Private: Display a notification' to 'Yes (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "DisableNotifications" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "InboundUserNotification"  >> "%filename%" >> "%filename%"

echo 1.1.1.4.1.1.2.6 Set 'Windows Firewall: Private: Apply local connection security rules' to 'Yes (default)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "AllowLocalIPsecPolicyMerge" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "LocalConSecRules"  >> "%filename%"

echo 1.1.1.4.1.1.2.7 Set 'Windows Firewall: Private: Firewall state' to 'On (recommended)' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile 2>nul | find /i "EnableFirewall" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show privateprofile   | find /i "State"  >> "%filename%"

:: 1.1.1.4.1.1.3 Public Profile
echo 1.1.1.4.1.1.3.1 Set 'Windows Firewall: Public: Outbound connections' to 'Allow (default)'  >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "DefaultOutboundAction" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "Firewall Policy"  >> "%filename%"

echo 1.1.1.4.1.1.3.2 Set 'Windows Firewall: Public: Apply local connection security rules' to 'Yes'  >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "AllowLocalIPsecPolicyMerge" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "LocalConSecRules"  >> "%filename%"

echo 1.1.1.4.1.1.3.3 Set 'Windows Firewall: Public: Apply local firewall rules' to 'Yes (default)'  >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "AllowLocalPolicyMerge" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "LocalFirewallRules"  >> "%filename%"

echo 1.1.1.4.1.1.3.4 Set 'Windows Firewall: Public: Allow unicast response' to 'No' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "DisableUnicastResponsesToMulticastBroadcast" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "UnicastResponseToMulticast"  >> "%filename%" 

echo  1.1.1.4.1.1.3.5 Set 'Windows Firewall: Public: Display a notification' to 'Yes' >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "DisableNotifications" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "InboundUserNotification"  >> "%filename%"

echo 1.1.1.4.1.1.3.6 Set 'Windows Firewall: Public: Inbound connections' to 'Enabled:Block (default)'  >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "DefaultInboundAction" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "Firewall Policy"  >> "%filename%"

echo 1.1.1.4.1.1.3.7 Set 'Windows Firewall: Public: Firewall state' to 'On (recommended)'  >> "%filename%"
echo Group Policy >> "%filename%"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile 2>nul | find /i "EnableFirewall" >> "%filename%"
echo Local Computer >> "%filename%"
netsh advfirewall show publicprofile   | find /i "State"  >> "%filename%"

:: 1.1.1.5 Account Policies
:: 1.1.1.5.1 Account Lockout Policy
echo 1.1.1.5.1.1 Set 'Account lockout duration' to '15' or greater   >> "%filename%"
net accounts | find "Lockout duration (minutes)" >> "%filename%"

echo 1.1.1.5.1.2 Set 'Account lockout threshold' to '6' or fewer   >> "%filename%"
type evid\cfg.ini | find /i "LockoutBadCount"    >> "%filename%"

echo 1.1.1.5.1.3 Set 'Reset account lockout counter after' to '15' or greater   >> "%filename%"
net accounts | find "Lockout observation window (minutes)" >> "%filename%"

:: 1.1.1.5.2 Password Policy
echo 1.1.1.5.2.1 Set 'Store passwords using reversible encryption' to 'Disabled'   >> "%filename%"
type evid\cfg.ini | find /i "ClearTextPassword"    >> "%filename%"

echo 1.1.1.5.2.2 Set 'Minimum password length' to '14' or greater   >> "%filename%"
type evid\cfg.ini | find /i "MinimumPasswordLength"    >> "%filename%"
 
echo 1.1.1.5.2.3 Set 'Maximum password age' to '60' or less   >> "%filename%"
type evid\cfg.ini | find /i "MaximumPasswordAge"    >> "%filename%"

echo 1.1.1.5.2.4 Set 'Enforce password history' to '24' or greater   >> "%filename%"
type evid\cfg.ini | find /i "PasswordHistorySize"    >> "%filename%"

echo 1.1.1.5.2.5 Set 'Minimum password age' to '1' or greater  >> "%filename%"
type evid\cfg.ini | find /i "MinimumPasswordAge"    >> "%filename%"

echo 1.1.1.5.2.6 Set 'Password must meet complexity requirements' to 'Enabled' >> "%filename%"
type evid\cfg.ini | find /i "PasswordComplexity"    >> "%filename%"

:: 1.2.1.1 Event Log Service
:: NOTE: IF no output, the setting is not configured. 
:: 1.2.1.1.1 Security (HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Security)
echo 1.2.1.1.1.1 Set 'Maximum Log Size (KB)' to 'Enabled:196608' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Eventlog\Security" 2>nul | find /i "maxSize" >> "%filename%"

echo 1.2.1.1.1.2 Set 'Retain old events' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Eventlog\Security" 2>nul | find /i "retention"    >> "%filename%"

:: 1.2.1.1.2 Application (HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application)
echo 1.2.1.1.2.1 Set 'Maximum Log Size (KB)' to 'Enabled:32768' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Eventlog\Application" 2>nul | find /i "maxSize"    >> "%filename%"

echo 1.2.1.1.2.2 Set 'Retain old events' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Eventlog\Application" 2>nul | find /i "retention"    >> "%filename%"

:: 1.2.1.1.3 System (HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\System)
echo 1.2.1.1.3.1 Set 'Maximum Log Size (KB)' to 'Enabled:32768' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Eventlog\System" 2>nul | find /i "maxSize"    >> "%filename%"

echo 1.2.1.1.3.2 Set 'Retain old events' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Eventlog\System" 2>nul |  find /i "retention" >> "%filename%"

:: 1.2.1.3 AutoPlay Policies
echo 1.2.1.3.1 Set 'Turn off Autoplay' to 'Enabled:All drives' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Polices\Explorer\" 2>nul | find /i "NoDriveTypeAutoRun" >> "%filename%" 

:: 1.2.1.4 Windows Installer
echo 1.2.1.4.1 Set 'Always install with elevated privileges' to 'Disabled' >> "%filename%"
reg query "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" 2>nul | find /i "AlwaysInstallElevated" >> "%filename%" 

echo Done. Report for Windows Server 2008 R2 is generated in %filename%
GOTO END

:END
:: END OF REPORT GENERATION
@echo:
pause
exit