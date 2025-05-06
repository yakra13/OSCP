# 172.16.X.14
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
`sudo find / -type f -iname "local.txt" 2>/dev/null`    
`sudo find / -type f -iname "proof.txt" 2>/dev/null`

- /home/mario/local.txt
# Accounts
### mario / ???
`ssh -i /home/mario/.ssh/id_rsa mario@172.16.152.14`   
`whoami /priv`
```

```
`whoami /groups`
```

```
# Enumeration
## NMAP
`sudo nmap -sV 192.168.141.97 --top-ports 1000`
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
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

```
