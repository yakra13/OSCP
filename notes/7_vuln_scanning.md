## Scanning with Nessus
https://www.tenable.com/downloads/nessus?loginAttempted=true

https://127.0.0.1:8843




## Scanning with NMAP
### NSE scripts
cd /usr/share/nmap/scripts/

cat script.db  | grep "\"vuln\""

### Try all vuln scripts against target
sudo nmap -sV -p 443 --script "vuln" 192.168.50.124

**vulners script shows CVSS scores to detect vulnerable CVEs

### get more nse scripts
google CVE-... nse -> find open scripts to add to nmap

sudo cp *.nse to /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse

sudo nmap --script-updatedb

sudo nmap -sV -p 443 --script "http-vuln-cve2021-41773" 192.168.50.124
