# SCION Packet Routing Unit Test

This directory contains tools to create, send, and validate SCION packets through the running SCION topology.


## Topology

### Overview (tiny-bgp.topo)

The test uses a 3-AS topology:

```
┌──────────────────────────────────────────────────────────────────────┐
│                         AS 64512 (CORE)                              │
│                    BR: 127.0.0.17:31002                              │
│                                                                      │
│   I1 ────► 127.0.0.4:50000 ────► 127.0.0.5:50000 ────┐               │
│   I2 ────► 127.0.0.6:50000 ────► 127.0.0.7:50000 ────┤               │
│   I3 ────► 127.0.0.8:50000 ────► 127.0.0.9:50000 ────┤               │
│   I4 ────► 127.0.0.10:50000 ───► 127.0.0.11:50000 ───┘               │
│                       (child links to 64513, 64514)                  │
└──────────────────────────────────────────────────────────────────────┘

       ▲                                            ▲
       │ 127.0.0.4:50000 ◄──── 127.0.0.5:50000      │ 127.0.0.8:50000 ◄──── 127.0.0.9:50000
       │ parent                                  parent
       │                                            │
       ▼                                            ▼
┌─────────────────────────┐            ┌─────────────────────────┐
│     AS 64513            │◄───peer───►│     AS 64514            │
│  BR: 127.0.0.25:31006   │ 127.0.0.12 │  BR: 127.0.0.33:31010   │
│   I1: 127.0.0.5         │ 127.0.0.14 │   I3: 127.0.0.13        │
│   I2: 127.0.0.7         │            │   I4: 127.0.0.15        │
│   I3: 127.0.0.12        │            │   I1: 127.0.0.9         │
│   I4: 127.0.0.14        │            │   I2: 127.0.0.11        │
└─────────────────────────┘            └─────────────────────────┘
```

### Border Router Details per AS

#### AS 64512 (Core)
- **BR**: br1-64512-1 @ 127.0.0.17:31002
- **Interfaces**:
  - I1: 127.0.0.4:50000 → 127.0.0.5:50000 (child to 1-64513)
  - I2: 127.0.0.6:50000 → 127.0.0.7:50000 (child to 1-64513)
  - I3: 127.0.0.8:50000 → 127.0.0.9:50000 (child to 1-64514)
  - I4: 127.0.0.10:50000 → 127.0.0.11:50000 (child to 1-64514)

#### AS 64513 (Test Source)
- **BR**: br1-64513-1 @ 127.0.0.25:31006
- **Interfaces**:
  - I1: 127.0.0.5:50000 → 127.0.0.4:50000 (parent to 1-64512)
  - I2: 127.0.0.7:50000 → 127.0.0.6:50000 (parent to 1-64512)
  - I3: 127.0.0.12:50000 → 127.0.0.13:50000 (peer to 1-64514)
  - I4: 127.0.0.14:50000 → 127.0.0.15:50000 (peer to 1-64514)

#### AS 64514 (Peer)
- **BR**: br1-64514-1 @ 127.0.0.33:31010
- **Interfaces**:
  - I1: 127.0.0.9:50000 → 127.0.0.8:50000 (parent to 1-64512)
  - I2: 127.0.0.11:50000 → 127.0.0.10:50000 (parent to 1-64512)
  - I3: 127.0.0.13:50000 → 127.0.0.12:50000 (peer to 1-64513)
  - I4: 127.0.0.15:50000 → 127.0.0.14:50000 (peer to 1-64513)

### Link Types

| Link Type | Description | Use Case |
|----------|------------|----------|
| PARENT | AS connects to core AS | Traffic to external ASes goes up to core |
| CHILD | Core AS connects to non-core | Core initiates to non-core |
| PEER | Non-core to non-core | Direct peering (bypasses core) |

### Test Routes

| # | From AS -> To AS | Interface | Underlay (local → remote) |
|--------|------|----------|------------------------|
| 1 | 64513 → 64512 | I1 | 127.0.0.5 → 127.0.0.4 |
| 2 | 64513 → 64512 | I2 | 127.0.0.7 → 127.0.0.6 |
| - | - | - | - |
| 3 | 64513 → 64514 | I3 | 127.0.0.12 → 127.0.0.13 |
| 4 | 64513 → 64514 | I4 | 127.0.0.14 → 127.0.0.15 |
| - | - | - | - |
| 5 | 64512 → 64514 | I | 127.0.0.12 → 127.0.0.13 |
| 6 | 64512 → 64514 | I | 127.0.0.14 → 127.0.0.15 |

### SCION-Mapped Addresses

These are IPv6 addresses derived from the AS configuration (config.sh):

| AS | SCION Address | Notes |
|----|-------------|-------|
| 1-64513 | fc00:10fc:100::1 | Host in AS64513 |
| 1-64514 | fc00:10fc:200::1 | Host in AS64514 |
| 1-64512 | fc00:10fc:000::1 | Host in AS64512 (core) |


### Understanding

#### Was bedeutet Local und Remote

Ein Interface in SCION ist ein UDP Tunnel zwischen zwei Border Routern
- Local: Die IP:Port auf unserer Seite, wo wir senden
- Remote: Die IP:Port auf der Nachbar-Seite, wo der andere lauscht

#### Warum 2 Links pro Nachbar?

Backup, Redundancy falls der erste Link down ist. 

#### IP Adressen für die zwei Routen:
Von AS 64513 zu AS 64514

- Peer Link (direkt)
    - 127.0.0.13:50000 <- Remote von Interface 3 (Ziel AS Peer Link)

- Via Core
    - 127.0.0.4:50000 <- Remote von Interface 1 (zu Parent)
    - 127.0.0.9:50000 <- Remote von Interface 1 (zu Ziel AS)

## Files

| File | Description |
|------|-------------|
| `create_and_send_scion_packet.py` | Creates and sends SCION packets |
| `README.md` | This file |

## Usage

### Prerequisites

#### Gen Topology

sudo ./scion.sh topology -c ./topology/tiny-bgp.topo

1. Start SCION network:
   ```bash
   cd /home/paul/Scintra/scion
   ./scion.sh start
   ```

2. Start monitoring (optional):
   ```bash
   cd /home/paul/Scintra/scion
   ./scion.sh start-monitoring
   ```

3. Verify SCION is running:
   ```bash
   cd /home/paul/Scintra/scion
   ./scion.sh status
   ```

## Create Packet

### Explanation

#### Aufbau

#### Erklärung

#### Warum passt es zur Topology

#### Usage


## SCION Monitoring

### Jaeger UI
- URL: http://localhost:16686
- Shows distributed traces

### Prometheus
- URL: http://localhost:9090
- Shows metrics

## Scapy Monitoring

## Sending Packet


# Scapy Scion Int

sudo /home/paul/Scintra/scapy-scion-int/.venv/bin/python /home/paul/Scintra/scapy-scion-int/scapy-scion


## ReadMe Packet Sending

https://github.com/lschulz/scapy-scion-int/tree/main


This example assumes the "tiny4" topology running on localhost. You can recreate this setup by running the following in the SCION repository.

./scion.sh topology -c topology/tiny4.topo

./scion.sh run

### 1.  Ping the target AS.

scion ping --sciond 127.0.0.19:30255 1-ff00:0:112,127.0.0.1 -c 1

Replace 127.0.0.19:30255 with the address of your SCION daemon and the destination AS with the AS you want to send packets to.

#### How do we find out what the SCION daemon address is?

ps au | grep scion

ss -lnp | grep -E "30255|30256|30257"

Also:

SCION deamon adress of our source AS?
127.0.0.27:30255

Destination AS: 64514, IPV6 adr?
1-64514
127.0.0.33:31010



scion ping --sciond 127.0.0.27:30255 1-64514,127.0.0.1 -c 1

###### Result:
```
paul@NetSys-Ubuntu24:~/Scintra/scion/bin$ ./scion ping --sciond 127.0.0.27:30255 1-64514,127.0.0.1 -c 1
Resolved local address:
  127.0.0.1
Using path:
  Hops: [1-64513 2>2 1-64512 4>2 1-64514] MTU: 1472 NextHop: 127.0.0.25:31006

PING 1-64514,127.0.0.1 pld=0B scion_pkt=112B
120 bytes from 1-64514,127.0.0.1: scmp_seq=0 time=14.809ms

--- 1-64514,127.0.0.1 statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 1006.877ms
rtt min/avg/max/mdev = 14.809/14.809/14.809/0.000 ms
```


### 2. Launch Scapy in a second terminal and capture one of the echo requests.

Replace IP 127.0.0.17 and port 31008 with the internal address of your border router.

#### Internal Address of our target Border Router

sudo ./scapy-scion
pkts = sniff(iface="lo",
    filter="host 127.0.0.17 and port 31008",
    lfilter=lambda pkt: pkt.haslayer(SCMP) and pkt[SCMP].type==128,
    prn=lambda pkt: pkt.summary(), count=1)

    Extract the IP/UDP underlay and the SCION header.

p = pkts[0][IP]
p[SCION].remove_payload()
del p[IP].len
del p[IP].chksum
del p[UDP].len
del p[UDP].chksum
del p[SCION].nh
del p[SCION].plen

    Build a new packet (e.g., a new echo request) and send it.

req = p/SCMP(message=ScmpEchoRequest(id=p[UDP].sport))/Raw(b"Hello!")
req[SCION].dl = 0
req[SCION].dst_host = "127.0.0.2"
resp = sr1(req, timeout=1)
resp.show()


## Tools for Examining SCION Traffic

https://github.com/lschulz/scapy-scion-int/tree/main/tools

(.venv) paul@NetSys-Ubuntu24:~/Scintra/scapy-scion-int$ sudo /home/paul/Scintra/scapy-scion-int/.venv/bin/python ./tools/local_trace.py -s /home/paul/Scintra/scion --br br1-64513-1 --dst 1-64514

--br from /home/paul/Scintra/scion/gen/AS64513/topology.json


### Ping destination AS
Resolved local address:
  127.0.0.1
Using path:
  Hops: [1-64513 1>1 1-64512 4>2 1-64514] MTU: 1472 NextHop: 127.0.0.25:31006

PING 1-64514,127.0.0.1 pld=0B scion_pkt=112B
120 bytes from 1-64514,127.0.0.1: scmp_seq=0 time=15.616ms

--- 1-64514,127.0.0.1 statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 31.548ms
rtt min/avg/max/mdev = 15.616/15.616/15.616/0.000 ms
### Trace probe packet
Sending probe to 127.0.0.25:31006:  SCION / UDP 6500 > 6500 / PROBEHDR
Hop Source           > br1-64513-1#i    |
Hop br1-64513-1#1    > br1-64512-1#1    | curr_hf = 1
Hop br1-64512-1#4    > br1-64514-1#2    | curr_inf= 1 curr_hf = 3 info_fields[0]/segid= 25231 info_fields[1]/segid= 51845
Hop br1-64514-1#i    > Destination      |


### Understand the trace tool.


### Sniffing and Saving Traffic Packets

Can we copy and adjust the trace script to save the package ping we send and once it is received also?

sudo /home/paul/Scintra/scapy-scion-int/.venv/bin/python ./tools/trace_scion.py -s /home/paul/Scintra/scion --src-as 64513 --dst-as 64514 -o my_trace

Save Options: -f .pkl | .pcap | .bin (default)

### Adjusting to pass custom scion packet to send.

