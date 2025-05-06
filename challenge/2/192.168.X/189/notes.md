# 192.168.X.189
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

- 
# Accounts
### username / password
`<connection method>`   
`whoami /priv`
```

```
`whoami /groups`
```

```
# Enumeration
## NMAP
`sudo nmap -sV 192.168.152.189 --top-ports 1000`
```
PORT     STATE SERVICE       VERSION
25/tcp   open  smtp          hMailServer smtpd
110/tcp  open  pop3          hMailServer pop3d
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp  open  imap          hMailServer imapd
445/tcp  open  microsoft-ds?
587/tcp  open  smtp          hMailServer smtpd
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: MAIL; OS: Windows; CPE: cpe:/o:microsoft:windows
```
`sudo nmap -A -T4 -p- 192.168.152.189`
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
// 245 246 247 248 249 14 7 191 15 19 20 DC
//249 web vuln upload
// mark somewhere 
```
