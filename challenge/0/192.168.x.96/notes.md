# VM 3 192.168.x.96
# Summary
- Gained initial access thru winrm and account 'apache'
- Knew mysql was on the box from initial nmap scans
- Found mysql as part of C:\xampp
- (forgot to record) found mysql login in a config file somewhere, root no password
- Enumerated the databases and found database 'creds' with table 'creds' containing 2 usernames and passwords
- Administrator turned out to be the local admin account and winrm back into box to obtain flag
- Tried winrm with the second username 'charlotte' on the .97 box and was successful
# Flag Location
`Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Include local.txt,proof.txt`
- C:\Users\Administrator\Desktop\proof.txt
- C:\Users\apache\Desktop\local.txt
# Accounts
### administrator   Almost4There8.?
`evil-winrm -i 192.168.159.96 -u 'administrator' -p 'Almost4There8.?`
### apache / New2Era4.!
`evil-winrm -i 192.168.159.96 -u 'apache' -p 'New2Era4.!'`
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled
```
```
GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users        Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```
# Enumeration
## NMAP
`sudo nmap -sV 192.168.141.96 --top-ports 100`

```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3306/tcp open  mysql         MariaDB 10.3.24 or later (unauthorized)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
## Local Users
`Get-LocalUser`
```
Name               Enabled Description
----               ------- -----------
Administrator      True    Built-in account for administering the computer/domain
apache             True
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
Remote Desktop Users                Members in this group are granted the right to logon remotely
Remote Management Users             Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.
Replicator                          Supports file replication in a domain
System Managed Accounts Group       Members of this group are managed by the system.
Users                               Users are prevented from making accidental or intentional system-wide changes and can run most applications
```
## System Info
`systeminfo`
```

```
## Routes
`route print`
```
===========================================================================
Interface List
 13...00 50 56 86 2f 6e ......vmxnet3 Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0  192.168.159.254   192.168.159.96     16
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
    192.168.159.0    255.255.255.0         On-link    192.168.159.96    271
   192.168.159.96  255.255.255.255         On-link    192.168.159.96    271
  192.168.159.255  255.255.255.255         On-link    192.168.159.96    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link    192.168.159.96    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link    192.168.159.96    271
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0  192.168.159.254       1
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
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       864
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       4164
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       548
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       684
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       540
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1332
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1552
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       2448
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       684
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       2256
  TCP    0.0.0.0:49671          0.0.0.0:0              LISTENING       664
  TCP    127.0.0.1:1337         0.0.0.0:0              LISTENING       5664
  TCP    192.168.159.96:139     0.0.0.0:0              LISTENING       4
  TCP    192.168.159.96:5985    192.168.45.219:40520   TIME_WAIT       0
  TCP    192.168.159.96:5985    192.168.45.219:59126   TIME_WAIT       0
  TCP    192.168.159.96:5985    192.168.45.219:60770   TIME_WAIT       0
  TCP    192.168.159.96:5985    192.168.45.219:60776   ESTABLISHED     4
  TCP    [::]:135               [::]:0                 LISTENING       864
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:3306              [::]:0                 LISTENING       4164
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       684
  TCP    [::]:49665             [::]:0                 LISTENING       540
  TCP    [::]:49666             [::]:0                 LISTENING       1332
  TCP    [::]:49667             [::]:0                 LISTENING       1552
  TCP    [::]:49668             [::]:0                 LISTENING       2448
  TCP    [::]:49669             [::]:0                 LISTENING       684
  TCP    [::]:49670             [::]:0                 LISTENING       2256
  TCP    [::]:49671             [::]:0                 LISTENING       664
  UDP    0.0.0.0:123            *:*                                    1048
  UDP    0.0.0.0:500            *:*                                    2240
  UDP    0.0.0.0:4500           *:*                                    2240
  UDP    0.0.0.0:5050           *:*                                    548
  UDP    0.0.0.0:5353           *:*                                    1088
  UDP    0.0.0.0:5355           *:*                                    1088
  UDP    0.0.0.0:56950          *:*                                    1088
  UDP    0.0.0.0:62044          *:*                                    1088
  UDP    127.0.0.1:1900         *:*                                    4620
  UDP    127.0.0.1:51605        *:*                                    684
  UDP    127.0.0.1:58666        *:*                                    4620
  UDP    127.0.0.1:59610        *:*                                    5160
  UDP    127.0.0.1:64957        *:*                                    2520
  UDP    192.168.159.96:137     *:*                                    4
  UDP    192.168.159.96:138     *:*                                    4
  UDP    192.168.159.96:1900    *:*                                    4620
  UDP    192.168.159.96:58665   *:*                                    4620
  UDP    [::]:123               *:*                                    1048
  UDP    [::]:500               *:*                                    2240
  UDP    [::]:4500              *:*                                    2240
  UDP    [::]:56950             *:*                                    1088
  UDP    [::]:62044             *:*                                    1088
  UDP    [::1]:1900             *:*                                    4620
  UDP    [::1]:58664            *:*                                    4620
```
## Environment Vars
`Get-ChildItem Env:`
```
Name                           Value
----                           -----
ALLUSERSPROFILE                C:\ProgramData
APPDATA                        C:\Users\apache.ERA\AppData\Roaming
CommonProgramFiles             C:\Program Files\Common Files
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
CommonProgramW6432             C:\Program Files\Common Files
COMPUTERNAME                   ERA
ComSpec                        C:\Windows\system32\cmd.exe
DriverData                     C:\Windows\System32\Drivers\DriverData
LOCALAPPDATA                   C:\Users\apache.ERA\AppData\Local
NUMBER_OF_PROCESSORS           2
OS                             Windows_NT
Path                           C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\apache.ERA\AppData\Local\Microsoft\WindowsApps
PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE         AMD64
PROCESSOR_IDENTIFIER           AMD64 Family 23 Model 1 Stepping 2, AuthenticAMD
PROCESSOR_LEVEL                23
PROCESSOR_REVISION             0102
ProgramData                    C:\ProgramData
ProgramFiles                   C:\Program Files
ProgramFiles(x86)              C:\Program Files (x86)
ProgramW6432                   C:\Program Files
PSModulePath                   C:\Users\apache.ERA\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC                         C:\Users\Public
SystemDrive                    C:
SystemRoot                     C:\Windows
TEMP                           C:\Users\apache.ERA\AppData\Local\Temp
TMP                            C:\Users\apache.ERA\AppData\Local\Temp
USERDOMAIN                     ERA
USERNAME                       apache
USERPROFILE                    C:\Users\apache.ERA
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


## Command History
```c
        // forgot to record history
    C:\xampp\mysql\bin> .\mysql.exe -u root -D creds -e "SELECT * FROM creds;"
        administrator   Almost4There8.?
        charlotte       Game2On4.!
```