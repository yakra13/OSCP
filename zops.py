import subprocess

'''
BASIC
    nmap -sS -Pn -n -T4 -vv 192.168.x.x
    nmap -sV -sC 192.168.x.x
    nmap --script vuln 192.168.x.x

SMB Enumeration (135, 139, 445)
    enum4linux -a 192.168.x.x
    smbclient -L //192.168.x.x/ -N
    smbmap -H 192.168.x.x
    crackmapexec smb 192.168.x.x --shares
    rpcclient -U "" 192.168.x.x

NetBIOS / Host Info
    nbtscan 192.168.x.x
    nmblookup -A 192.168.x.x

WinRM / RDP
    nmap -p 5985,5986 --script http-winrm-enum 192.168.x.x
    xfreerdp /u:user /p:password /v:192.168.x.x

Web Services (IIS / AppManager / etc)
    whatweb http://192.168.x.x
    nikto -h http://192.168.x.x
    gobuster dir -u http://192.168.x.x -w /usr/share/wordlists/dirb/common.txt

Shell On Box
    systeminfo
    whoami /priv
    ipconfig /all
    net user
    net localgroup administrators
    netstat -ano
Enumerate AV / Patch Status / Interesting Files:
    tasklist /v
    wmic qfe get Caption,Description,HotFixID,InstalledOn
    dir /s /b C:\Users\*.txt
PowerShell Enumeration (via shell)
    Import-Module .\PowerView.ps1
    Get-NetUser
    Get-NetGroup
    Get-NetComputer
Domain / AD Enumeration (if on domain)
    crackmapexec smb 192.168.x.x -u 'user' -p 'pass' --lsa
    ldapsearch -x -H ldap://192.168.x.x -b "dc=domain,dc=local"
    bloodhound-python -u user -p pass -d domain.local -c all -dc-ip 192.168.x.x

Exploit / Vulnerability Tools
searchsploit
msfconsole + use exploit/windows/smb/ms17_010_eternalblue (for legacy boxes)
exploitdb or CVE lookup once you identify services
'''

def run_command() -> None:
    cmd = ['nmap', '-sV', '-Pn', '-T4', 'ip address']
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)

class Port():
    port: int
    service: str

class Machine():
    os: str = ''
    ip: str = '0.0.0.0'
    open_ports: list[Port]
    def __init__(self):
        pass
