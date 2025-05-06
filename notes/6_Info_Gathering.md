# Passive
## WHOIS
whois megacorpone.com -h 192.168.50.251

## Google Hacking
site:<site> filetype:txt -filetype:html intitle: "index of" "parent directory"
(-filetype -> not html in this case)
https://www.exploit-db.com/google-hacking-database

## Netcraft
https://www.netcraft.com/

## Open source code
github and stuff

## Shodan
https://www.shodan.io/

## Security Headers and SSL/TLS
https://securityheaders.com/

# Active
## DNS
host www.megacorpone.com
-t mx, txt -> mail records, text
for ip in $(cat list.txt); do host $ip.megacorpone.com; done
(checking for ftp.mega... mail.mega... etc)

dnsrecon -d megacorpone.com -t std
python script to check buncha stuff
dnsrecon -d megacorpone.com -D ~/list.txt -t brt
brute force version

dnsenum megacorpone.com

windows
nslookup mail.megacorptwo.com
nslookup -type=TXT info.megacorptwo.com 192.168.50.151

## TCP/UDP Port Scanning Theory
Time out and z send no data
nc -nvv -w 1 -z 192.168.50.152 3388-3390
UDP scan
nc -nv -u -z -w 1 192.168.50.149 120-123

## NMAP
NSE scripts /usr/share/nmap/scripts
nmap --script-help http-title
nmap --script http-title -p 80,443 192.168.119.0/24

## SMB servers
nmap -v -p 139,445 -oG smb.txt 192.168.119.1-254

### windows rdp from kali
xfreerdp -> sudo apt install freerdp2-x11
xfreerdp /u:Administrator /p:MySecurePassword /v:192.168.1.10
rdesktop -u student -p lab 192.168.119.149
net view \\dc01 /all

enum4linux <target-ip> -> enumerates windows machines using SMB protocol (users, passwd policies, shares, groups, OS info, domain info, etc )
cat smb.txt | grep 445/open | awk '{print $2}' | xargs -n1 enum4linux > results.txt

## SMTP
port 25
nc <ip> 25 -> VRFY root
252 response (not confirm or deny user but try to deliver messages anyway)

## SNMP
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
### get info
snmpwalk -c public -v1 -t 10 192.168.50.151
-Oa to convert hex to ascii (useful for above command)
OID--------------------------------------------\/
### currently running processes
snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2




