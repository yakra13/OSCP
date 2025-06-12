# 192.168.X.250
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
`sudo find / -type f -iname "local.txt" 2>/dev/null`    
`sudo find / -type f -iname "proof.txt" 2>/dev/null`

- NONE
# Accounts
### offsec / lab
`xfreerdp3 /u:offsec /p:lab /v:192.168.152.250`   
`whoami /priv`
```
Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
`whoami /groups`
```
Group Name                                                    Type             SID          Attributes                  
============================================================= ================ ============ ==================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Group used for deny only    
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny only    
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON                         Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
```
# Enumeration
## NMAP
`sudo nmap -sV 192.168.152.250 --top-ports 1000`
```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
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
Administrator      False   Built-in account for administering the computer/domain
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
offsec             True
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scen...
```
## Local Groups
`Get-LocalGroup`
```
Name                                Description
----                                -----------
Access Control Assistance Operators Members of this group can remotely query authorization attributes and permission...
Administrators                      Administrators have complete and unrestricted access to the computer/domain
Backup Operators                    Backup Operators can override security restrictions for the sole purpose of back...
Cryptographic Operators             Members are authorized to perform cryptographic operations.
Device Owners                       Members of this group can change system-wide settings.
Distributed COM Users               Members are allowed to launch, activate and use Distributed COM objects on this ...
Event Log Readers                   Members of this group can read event logs from local machine
Guests                              Guests have the same access as members of the Users group by default, except for...
Hyper-V Administrators              Members of this group have complete and unrestricted access to all features of H...
IIS_IUSRS                           Built-in group used by Internet Information Services.
Network Configuration Operators     Members in this group can have some administrative privileges to manage configur...
Performance Log Users               Members of this group may schedule logging of performance counters, enable trace...
Performance Monitor Users           Members of this group can access performance counter data locally and remotely
Power Users                         Power Users are included for backwards compatibility and possess limited adminis...
Remote Desktop Users                Members in this group are granted the right to logon remotely
Remote Management Users             Members of this group can access WMI resources over management protocols (such a...
Replicator                          Supports file replication in a domain
System Managed Accounts Group       Members of this group are managed by the system.
Users                               Users are prevented from making accidental or intentional system-wide changes an...
```
## System Info
`systeminfo`
```
Host Name:                 WINPREP
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22000 N/A Build 22000
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          offsec
Registered Organization:
Product ID:                00328-90000-00000-AAOEM
Original Install Date:     9/26/2022, 4:18:02 PM
System Boot Time:          4/10/2025, 10:58:11 AM
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
Available Physical Memory: 2,294 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 3,146 MB
Virtual Memory: In Use:    1,653 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\WINPREP
Hotfix(s):                 4 Hotfix(s) Installed.
                           [01]: KB5017024
                           [02]: KB5012170
                           [03]: KB5017328
                           [04]: KB5018291
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.152.250
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
## Routes
`route print`
```
===========================================================================
Interface List
  3...00 50 56 86 5f a0 ......vmxnet3 Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0  192.168.152.254  192.168.152.250     16
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
    192.168.152.0    255.255.255.0         On-link   192.168.152.250    271
  192.168.152.250  255.255.255.255         On-link   192.168.152.250    271
  192.168.152.255  255.255.255.255         On-link   192.168.152.250    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link   192.168.152.250    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link   192.168.152.250    271
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0  192.168.152.254       1
===========================================================================

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    331 ::1/128                  On-link
  1    331 ff00::/8                 On-link
===========================================================================
Persistent Routes:
  None
```
## Netstat
`netstat -ano`
```
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       932
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       876
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       5612
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       708
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       568
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1556
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1724
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       1992
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       676
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       2772
  TCP    192.168.152.250:139    0.0.0.0:0              LISTENING       4
  TCP    192.168.152.250:3389   192.168.45.219:45028   ESTABLISHED     876
  TCP    192.168.152.250:50153  40.126.28.11:443       SYN_SENT        3368
  TCP    192.168.152.250:50154  4.175.87.197:443       SYN_SENT        3660
  TCP    [::]:135               [::]:0                 LISTENING       932
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:3389              [::]:0                 LISTENING       876
  TCP    [::]:49664             [::]:0                 LISTENING       708
  TCP    [::]:49665             [::]:0                 LISTENING       568
  TCP    [::]:49666             [::]:0                 LISTENING       1556
  TCP    [::]:49667             [::]:0                 LISTENING       1724
  TCP    [::]:49668             [::]:0                 LISTENING       1992
  TCP    [::]:49669             [::]:0                 LISTENING       676
  TCP    [::]:49670             [::]:0                 LISTENING       2772
  UDP    0.0.0.0:123            *:*                                    6048
  UDP    0.0.0.0:500            *:*                                    2636
  UDP    0.0.0.0:3389           *:*                                    876
  UDP    0.0.0.0:4500           *:*                                    2636
  UDP    0.0.0.0:5050           *:*                                    5612
  UDP    0.0.0.0:5353           *:*                                    1492
  UDP    0.0.0.0:5355           *:*                                    1492
  UDP    0.0.0.0:57781          *:*                                    1492
  UDP    0.0.0.0:58928          *:*                                    1492
  UDP    127.0.0.1:1900         *:*                                    4140
  UDP    127.0.0.1:52088        127.0.0.1:52088                        2664
  UDP    127.0.0.1:57792        *:*                                    4140
  UDP    192.168.152.250:137    *:*                                    4
  UDP    192.168.152.250:138    *:*                                    4
  UDP    192.168.152.250:1900   *:*                                    4140
  UDP    192.168.152.250:57791  *:*                                    4140
  UDP    [::]:123               *:*                                    6048
  UDP    [::]:500               *:*                                    2636
  UDP    [::]:3389              *:*                                    876
  UDP    [::]:4500              *:*                                    2636
  UDP    [::]:57781             *:*                                    1492
  UDP    [::]:58928             *:*                                    1492
  UDP    [::1]:1900             *:*                                    4140
  UDP    [::1]:57790            *:*                                    4140
```
## Environment Vars
`Get-ChildItem Env:`
```
Name                           Value
----                           -----
ALLUSERSPROFILE                C:\ProgramData
APPDATA                        C:\Users\offsec\AppData\Roaming
CLIENTNAME                     kali
CommonProgramFiles             C:\Program Files\Common Files
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
CommonProgramW6432             C:\Program Files\Common Files
COMPUTERNAME                   WINPREP
ComSpec                        C:\Windows\system32\cmd.exe
DriverData                     C:\Windows\System32\Drivers\DriverData
HOMEDRIVE                      C:
HOMEPATH                       \Users\offsec
LOCALAPPDATA                   C:\Users\offsec\AppData\Local
LOGONSERVER                    \\WINPREP
NUMBER_OF_PROCESSORS           2
OneDrive                       C:\Users\offsec\OneDrive
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
PSModulePath                   C:\Users\offsec\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShel...
PUBLIC                         C:\Users\Public
SESSIONNAME                    RDP-Tcp#0
SystemDrive                    C:
SystemRoot                     C:\Windows
TEMP                           C:\Users\offsec\AppData\Local\Temp
TMP                            C:\Users\offsec\AppData\Local\Temp
USERDOMAIN                     WINPREP
USERDOMAIN_ROAMINGPROFILE      WINPREP
USERNAME                       offsec
USERPROFILE                    C:\Users\offsec
windir                         C:\Windows
```
## Domain Controller Info
`nltest /dsgetdc:relia`
```

```
# Services    
## API Endpoints
`gobuster dir -u http://192.168.159.121:80 -w /usr/share/wordlists/dirb/big.txt -p pattern`
```

```

# Command History
```c

```
