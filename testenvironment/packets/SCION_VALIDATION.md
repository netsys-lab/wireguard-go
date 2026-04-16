# SCION Packet Validation Guide

Dieses Dokument erklärt wie wir unser SCION Packet durch die SCION Topology schicken können um zu validieren, dass es ein gültiges SCION Packet ist.

## Was wir testen wollen

Wir haben ein SCION Packet erstellt (`scion_client_to_server.bin`), das die Translation unseres IP Packets repräsentiert. Jetzt wollen wir:

1. **Validieren**: Das Packet ist ein gültiges SCION Packet (kann von scapy-scion-int geparst werden)
2. **Senden**: Das Packet an den Border Router schicken (127.0.0.25:31006)
3. **Empfangen**: Mit tcpdump/scapy am BR sehen dass es ankommt
4. **Verarbeiten**: Der BR erkennt es als SCION und verarbeitet es

## Voraussetzungen

1. SCION Topology muss generiert sein und laufen
2. scapy-scion-int muss verfügbar sein: `/home/paul/Scintra/scapy-scion-int`
3. SCION muss auf localhost Ports lauschen

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Client Namespace (kein SCION)                     │
│   wg-client: fd00::2                                               │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ IP Packet (fd00::2 → fc00:10fc:100::1)
                           │ (SCION-mapped destination)
                           ↓
┌──────────────────────────┬──────────────────────────────────────────┐
│                    Server Namespace                                 │
│                                                                       │
│   wg-server: fd00::1                                               │
│         ↓ IP Packet from TUN                                         │
│   ┌─────────────────────────────────────────┐                        │
│   │           Translator                    │                        │
│   │  IP (IPv6) → SCION                       │                        │
│   │  fd00::2 → fc00:10fc:100::1             │                        │
│   │  (1-64514) → (1-64513)                  │                        │
│   └─────────────────────────────────────────┘                        │
│         ↓ SCION Packet                                              │
│   ┌─────────────────────────────────────────┐                        │
│   │      Border Router AS64513              │                        │
│   │      127.0.0.25:31006                   │                        │
│   └─────────────────────────────────────────┘                        │
│         ↓                                                            │
│   ┌─────────────────────────────────────────┐                        │
│   │         SCION Topology                  │                        │
│   │                                         │                        │
│   │     1-64512 (Core)                      │                        │
│   │         ↑                               │                        │
│   │       CHILD                             │                        │
│   │         ↑                               │                        │
│   │   1-64513 ──PEER── 1-64514             │                        │
│   │  (Server)               (Target)        │                        │
│   │                                       │                        │
│   └─────────────────────────────────────────┘                        │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

## Topology Overview

### tiny-bgp Topology (3 ASes)

- **AS64512**: Core AS (parent) - keine BR in unserer Umgebung
- **AS64513**: Server AS - BR: 127.0.0.25:31006 - **wo wir Pakete hinschicken**
- **AS64514**: Target AS - BR: 127.0.0.33:31010 - wo Pakete hingeroutet werden sollen

### Border Router Details

| AS | BR Internal Addr | Port |
|----|------------------|------|
| AS64513 | 127.0.0.25 | 31006 |
| AS64514 | 127.0.0.33 | 31010 |

### Link Types

- **CHILD**: 64512 → 64513, 64512 → 64514 (hierarchisch)
- **PEER**: 64513 ↔ 64514 (direkte Verbindung)

## Packet Flow

### Our Test Packet: scion_AS64513_to_AS64514.bin

Dieses Packet testet die Topologie-Routing von AS64513 zu AS64514:

```
Source:      AS 1-64513 (Server AS)
Dest:        AS 1-64514 (Target AS)
Underlay:    10.0.0.1 → 127.0.0.25:31006 (AS64513 Border Router)
SCION Host:  fc00:10fc:100::1 (Server) → fc00:10fc:200::2 (Client)
Payload:     TEST123
```

**Flow:**
1. Packet sent to AS64513 BR (127.0.0.25:31006)
2. BR reads SCION header (dst=1-64514)
3. BR routes through topology via PEER link
4. Packet arrives at AS64514 BR (127.0.0.33:31010)

**Verified**: Packet captured at both BRs - topology routing works!

**Flow:**
1. Client sends IP packet to SCION-mapped address
2. Server translates: IP → SCION (Src AS=64513, Dst AS=64514)
3. Server sends to BR at 127.0.0.25:31006
4. BR routes through topology to AS64514 via PEER link

```
SCION Packet (64513 → 64514)
    ↓
wg-server TUN (nach Translation)
    ↓
An BR schicken: 127.0.0.25:31006 (AS64513)
    ↓
BR erkennt SCION Header
    ↓
Routing durch Topology (PEER link)
    ↓
Weiterleitung zu AS64514 (127.0.0.33:31010)
```

**Wichtig**: 
- Src: 1-64513, Dst: 1-64514
- Das Ziel ist NICHT lokal, also ROUTET der BR durch die Topology zu AS64514

## Validating SCION Packets

### Step 1: Starte SCION Topology

```bash
# Im Server Namespace
ip netns exec Server /home/paul/Scintra/scion/bin/scion run &
```

### Step 2: Parse Packet with scapy-scion-int

```bash
cd /home/paul/Scintra/scapy-scion-int
sudo ./scapy-scion
```

```python
from scapy.all import *
from scapy_scion.layers.scion import SCION, SCIONPath

# Load our packet
with open('/home/paul/Scintra/wireguard-go/testenvironment/packets/scion/scion_client_to_server.bin', 'rb') as f:
    pkt_bytes = f.read()

pkt = Packet(pkt_bytes)
pkt.show()

# Check SCION layer
if SCION in pkt:
    print(f"Source IA: {pkt[SCION].src_isd}-{pkt[SCION].src_asn}")
    print(f"Dest IA: {pkt[SCION].dst_isd}-{pkt[SCION].dst_asn}")
    print(f"Source Host: {pkt[SCION].src_host}")
    print(f"Dest Host: {pkt[SCION].dst_host}")
```

### Step 3: Send Packet to Border Router

Das SCION Packet an den Border Router schicken:

```python
# Im Server Namespace
from scapy.all import *
from scapy_scion.layers.scion import SCION

# Unser Packet
with open('/home/paul/Scintra/wireguard-go/testenvironment/packets/scion/scion_client_to_server.bin', 'rb') as f:
    pkt_bytes = f.read()

# Das Packet enthält bereits IPv4 underlay, also direkt senden
send(Raw(pkt_bytes))
# Oder besser: nur der SCION Teil

# Alternative: Nur SCION Teil senden
scion_pkt = pkt_bytes[20:]  # Skip IPv4 header
send(IP(dst='127.0.0.25')/UDP(sport=32766, dport=31006)/scion_pkt)
```

### Step 4: Capture at Border Router

```bash
# Capture am BR Port
ip netns exec Server tcpdump -i lo -nn port 31006 -c 5

# Oder mit scapy
ip netns exec Server python3 -c "
from scapy.all import *
from scapy_scion.layers.scion import SCION

def handler(pkt):
    if SCION in pkt:
        print(f'SCION: {pkt[SCION].src_isd}-{pkt[SCION].src_asn} -> {pkt[SCION].dst_isd}-{pkt[SCION].dst_asn}')
        pkt[SCION].show()

sniff(iface='lo', filter='port 31006', prn=handler, count=3)
"
```

## Validation Checklist

- [ ] SCION packet is recognized by scapy-scion-int (kann geparst werden)
- [ ] SCION header fields are correctly set (ISD-AS, host addresses)
- [ ] Underlay IP/UDP points to correct BR (127.0.0.25:31006)
- [ ] Packet arrives at BR port when sent (tcpdump capture)
- [ ] BR accepts and processes the packet (keine Fehler in logs)
- [ ] Packet wird durch Topology weitergeleitet (falls Ziel ≠ lokale AS)

## Test Szenarien

### Test 1: Lokale Zustellung
- SCION Packet: Src=1-64514, Dst=1-64513
- Erwartet: BR lehnt es ab oder leitet es lokal zu

### Test 2: Routing durch Topology
- SCION Packet: Src=1-64513, Dst=1-64514
- Erwartet: BR leitet es über PEER Link zu AS64514 weiter

## Debugging

### Check SCION Status
```bash
ip netns exec Server /home/paul/Scintra/scion/bin/scion status
```

### Check BR logs
```bash
ip netns exec Server tail -f /home/paul/Scintra/scion/gen/AS64513/logs/br1-64513-1.log
```

### Capture all SCION traffic
```bash
ip netns exec Server sudo tcpdump -i lo -nn port 31006 or port 31010 -w /tmp/scion.pcap
```

## References

- [scapy-scion-int](https://github.com/netsys-lab/scapy-scion-int)
- [SCION Documentation](https://docs.scion.org)
