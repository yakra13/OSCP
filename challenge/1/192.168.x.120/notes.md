# VM 3 192.168.x.120
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
`sudo nmap -sV 192.168.141.97 --top-ports 1000`
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    WEBrick httpd 1.6.1 (Ruby 2.7.4 (2021-07-07))
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