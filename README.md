# Host-Assessment-Tool-HAT

Host Assessment Toolkit (HAT) is a semi-automated script file that collect system configuration value listed in CIS recommended benchmark.

## Supported System
1. Windows (use Scgary)
2. CentOS

- - - -

## Windows

### Windows Security Policy
secpol.msc = Local Security Policy 
 - Can export
 - gpupdate /force

gpedit.msc = Local Group Policy
 - Event Log service Policy (Can't Export)
 
 
- - - -


**Information about each service on the system**
```bat
reg query "HKLM\SYSTEM\CurrentControlSet\services" /s
```

**NIC**
```powershell
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName . | Select-Object -Property [a-z]* -ExcludeProperty IPX*,WINS*
```
