# Test Environment Setup

## Installing & Running Scion

https://docs.scion.org/en/latest/dev/setup.html

### Setup Docker:
https://docs.docker.com/engine/install/ubuntu/

#### Fixing Possible Errors:

Docker-Deamon läuft nicht:
sudo systemctl status docker
sudo systemctl start docker
sudo systemctl enable docker   # optional

User hat keine Rechte auf docker.sock
sudo usermod -aG docker "$USER"
newgrp docker            # oder einmal ab- und wieder anmelden
docker info              # sollte jetzt ohne sudo gehen

### Running Scion Locally

https://docs.scion.org/en/latest/dev/run.html

#### Tiny Topo

./scion.sh topology -c topology/tiny.topo

./scion.sh run

bin/end2end_integration

bin/scion showpaths --sciond $(./scion.sh sciond-addr 112) 1-ff00:0:110

./scion.sh stop

## Setup Wireguard & Scion

### Wie funktioniert Wireguard:

TUN-Device wird erstellt, ein virtuelles IP-Interface. Zugriff über /dev/net/tun
Transporiter Layer 3 IP-Pakete

Wireguard öffnet einen UDP-Socket mit ganz normalem Port (default: 51820)
Ein Socket in Linux verbindet ein Programm mit dem Netzwerk Stack. Hat ein Typ, Protokollfamilie und Adresse + Port.

Kernel Empfängt ein UDP-Paket auf Port 51820.
Schaut welcher UDP-Socket dazu passt und leitet das Paket in den Puffer dieses Sockets.
Wireguard ruft recvfrom() oder ReadFromUDP() auf? und liest aus dem Puffer

Paket wird entschlüsslet

Paket wird ins TUN-Interface geschoben und dort auf den Empfangspfad geschrieben (wg0)

Von hier kann der Kernel nun das Paket sehen und leitet es mit der dst IP weiter


### Wie funktioniert die SCION Topology:

Die laufende Topology hat immer einen Dispatcher Prozess und meine eigenen Programme (Border Router) rede mit ihm über ein UNIX-Socket.

Der Dispatcher ist lokal und alle Programme sprechen mit demselben Dispatcher über einen Unix-Socket (oder aber auch einen UDP Socket?)

Und der Dispatcher reicht es weiter an den Border Router-

### Paket von Wireguard zu SCION:

Wireguard schreibt das decrypted Paket ins TUN-Interface. Wir können einen eigenen Prozess benutzten um TUN Interface auszulesen und die Pakete zu verschicken.


Direkt an den Border Router über dessen Underlay-Port senden, am Dispatcher Vorbei. Also direkt nach der Verschlüsselung. Der Borderrouter liest Underlay-UDP-Pakete und erkennt SCION-Header.

Wenn nun Wireguard und Scion prozesse den gleichen Underlay-Port benutzen, also denselben UDP-Socket?

Übergabe über den Dispatcher welcher liefert es an den richtigen Border Router und der sendet es dann über seinen Underlay-Link weiter.

Warum nicht der Dispatcher?

Also unser Paket das ankommt ist ein vollwertiges SCION-Underlay-Paket?
So ablegen des der lokale Border Router es auf seinem Underlay-Socket empfängt.

Wir Öffnen eunen UDP Socket und senden dann den UDP Payload, das SCION-Paket, an den Socket. Wenn dort der Border Router Underlay listener wartet, liest er diese Bytes.
Dies passiert unmittelbar nach der decryption, dort wo wir momentan auf das TUN Device schreiben?


#### Mögliche Probleme:
Source-IP/Port stimmen nicht:
	Der BR prüft normalerweise, ob das Paket von der erwarteten Nachbar-Underlay-Adresse kommt. Wenn dein WireGuard-Peer eine andere IP hat (z. B. 10.0.0.x statt 127.0.0.1), droppt er es.
Firewall/LocalDelivery:
	Wenn der BR auf 127.0.0.1:30041 hört, aber dein WireGuard-Socket von einer anderen Address-Family sendet, nimmt der Kernel es evtl. nicht an.
MTU:
	WireGuard + SCION Header zusammen → reduzierte MTU. Du musst ggf. fragmentieren.



### Scion Paket innerhalb der SCION Topology vershciken


## Overview

IP-Paket bauen

IP-Paket an Wireguard übergeben.

IP-Paket wird übersetzt, verschlüsselt und dann versendet.

Verschlüsseltes Paket wird empfangen und entschlüsselt.

Das entschlüsselte SCION-Paket wird an den Underlay-Port des Border Routers übergeben.

Feedback Lars:

SCION UDP Underlay adresse des Border Routers wrapped um das Scion paket, IP und UDP über SCION für den Border Router.

Also jetzt einfach nur Script das ein Scion Paket baut und diese Erfolgreich an die Scion Topology schickt.

Und dann das Paket anzeigen mit einem Dump

IP Packet bauen und über den Tunnel schicken.



# IP Packet duch Wireguard-go tunnel

## Steps

Namespace aufbauen:
./namespace-tunnel.sh up

Tunnel aufbauen:
./wg_tunnel.sh up verbose

In einen namespace:
sudo ip netns exec Client bash

python venv aktivieren:
source /home/paul/scion/bin/activate

script ausführen:
python send_ip_packet.py --dst 10.10.10.1 --port 51820 --src 10.10.10.2

In einem anderen Terminal Live überprüfen ob ein Paket geschickt wurde:
sudo ip netns exec Client bash
und dann:
sudo tcpdump -i wg-client -nn 'ip or ip6'
Oder in einem cmd, aber dann ausgabe erst nach cancel.

IP Route checken:
ip route get 10.10.10.1

*Possible TODO: Das ganze in ein shell script?*

# Scion Packet zu/druch SCION topology

Scion Topology muss laufen. Damit haben wir dann:
ASes
border router
SCIOND deamons
dispatchers (Die machen aber nicht mehr viel?)

Das ist die Infrastruktur

Scion starten

Scion Packet bauen:

go build -o scion-client scion-client.go

export SCION_DAEMON_ADDRESS=127.0.0.1:30255
export DISPATCHER_SOCKET=/run/shm/dispatcher/default.sock   # falls deine topologie das so nutzt

./scion-client -srcIA 1-ff00:0:110 -srcIP 127.0.0.1 \
  -dstIA 1-ff00:0:111 -dstIP 127.0.0.1 -dstPort 4242 \
  -data "Test packet"

Scion Packet Dump speichern



# Debugger

ps aux | grep ./wireguard-go

Get Prozess ID

Put Prozess ID here:

sudo dlv attach [Prozes ID]   --headless --listen=127.0.0.1:40000   --api-version=2 --accept-multiclient   --only-same-user=false

sudo sysctl -w kernel.yama.ptrace_scope=0

sudo setcap cap_sys_ptrace=eip $(which dlv)

sudo dlv attach 7656   --headless --listen=127.0.0.1:40000   --api-version=2 --accept-multiclient   --only-same-user=false




