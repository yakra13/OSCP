# VM 3 192.168.x.121
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


```