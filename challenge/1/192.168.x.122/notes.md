# 192.168.x.122
# Summary
- 
# Flag Location
`Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Include local.txt,proof.txt`
- 
# Accounts
### ???
`<access command>`
```

```
# Enumeration
## NMAP
`sudo nmap -sV 192.168.159.122 --top-ports 1000`
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
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
`nltest /dsgetdc:secura`
```
```
# Services    


## Command History
```c

```