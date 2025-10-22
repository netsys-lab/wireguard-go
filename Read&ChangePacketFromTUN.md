

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

IPv4:
python send_ip_packet.py --dst 10.10.10.1 --port 51820 --src 10.10.10.2


##### Sending IPv6 Packets.

Underlay Veth + Wireguard Verbindung muss nicht IPv6 sein. 
IPv6 Pakete können im Overlay (Wireguard Tunnel) auch verschickt werden wenn das Underlay rein IPv4 ist.

IPv6:
python send_ip_packet.py --dst 'fe80::1%wg-client' --port 51820 --src 'fe80::1%wg-client' --iface wg-client

%wg-client für den Scope 

alternativ:
python send_ip_packet.py --dst fd00::1 --src fd00::2 --port 51820 --iface wg-client

Port 51820 ist bei WireGuard der äußere UDP-Port auf dem Underlay. Auf der wg-Schnittstelle (L3, „innen“) ist 51820 einfach irgendein UDP-Port; das ist ok, nur konzeptionell nicht „WireGuard-Handshake“


#### Attach Debugger

ps aux | grep ./wireguard-go

Get Prozess ID

Put Prozess ID here:

sudo dlv attach [Prozes ID]   --headless --listen=127.0.0.1:40000   --api-version=2 --accept-multiclient   --only-same-user=false

### Read Buffer from TUN

Func to Procss Packet

    Func to Read Packet

    Func to Modify Packet

    Func to Serialize Packet

What we have:

Ip Packet kommt im TUN an

wir können Bytes auslesen:

STEP 1:
Bytes deserializes - Ändern - serializen und wieder in Buffer schreiben - und paket soll funktionieren. (Längen änderungen)

Also haben wir bytes fürs Scion Paket
Was brauchen wir noch?

STEP 2:
Erstmal wird DST IP abgelesen
DST IP zu SCION Adress

Step 3:
Brauchen PathCache? Vorlage von Lars (c++) brauchen wir in GO - Fidelio hat vielleicht was

Dann nach SCION Adress in Path Cache suchen
Wenn nicht im PathCache - Nest step, Neue Paths anfragen

STEP 4:
Wie neue Paths anfragen - Deamon