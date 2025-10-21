

### Setup

Start Namespaces

Start Wireguard Tunnel

#### TCP Dump on Interface to check if Paket reaches Interfaces

##### Client
In einen namespace:
sudo ip netns exec Client bash
dann:
sudo tcpdump -v -i wg-client -nn 'ip or ip6'

##### Server
In einen namespace:
sudo ip netns exec Client bash
dann:
sudo tcpdump -v -i  wg-client -nn 'ip or ip6'

##### set the hostname (if needed)
Falls das hier:
sudo: unable to resolve host NetSys-Ubuntu24: Temporary failure in name resolution
dann hostname setzen (beschreibung unten)

sudo hostnamectl set-hostname NetSys-Ubuntu24
(Outside of namespaces)

#### Send Ip Packet through tunnel
In einen namespace:
sudo ip netns exec Client bash

python venv aktivieren:
source /home/paul/scion/bin/activate

script ausführen:
python send_ip_packet.py --dst 10.10.10.1 --port 51820 --src 10.10.10.2

#### Attach Debugger


### Read Buffer from TUN

