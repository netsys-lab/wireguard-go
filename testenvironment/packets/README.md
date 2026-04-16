# Test Packets Summary

This document describes the test packets created for the SCION-WireGuard integration test environment.

## Overview

The test packets are designed to validate the IP ↔ SCION translation by testing packet flow through the SCION topology. We create paired packets:

1. **IP Packets**: IPv6/UDP packets with SCION-mapped addresses
2. **SCION Packets**: Same packets translated to SCION format with IPv4 underlay

## Topology Context

Die Test-Pakete sind für folgende Umgebung designed:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Client Namespace                             │
│                                                                     │
│   ┌──────────────┐         WireGuard Tunnel                        │
│   │ wg-client    │ ══════════════════════════════════╗            │
│   │ fd00::2      │                                 ║            │
│   └──────────────┘                                 ║            │
│         │                                           ║            │
│         │ IP Packet (fd00::2 → fc00:10fc:100::1)    ║            │
│         │ SCION-mapped Address                      ║            │
│         ↓                                           ↓            │
└───────╦───────────────────────────────────────────╦──────────────┘
        ║                                           ║
        ║    (veth: 10.0.0.2 ↔ 10.0.0.1)            ║
        ║                                           ║
        ↓                                           ↓
┌───────────────────────────────────────────────────────────────────────┐
│                         Server Namespace                              │
│                                                                       │
│   ┌──────────────┐                                                   │
│   │ wg-server    │ ← IP/UDP entpackt, ins TUN geschrieben            │
│   │ fd00::1     │     ↓                                               │
│   └──────────────┘     ↓ Translation: IP → SCION                     │
│         │              ↓                                               │
│         │         ┌──────────────┐                                    │
│         └────────→│ Translator   │                                    │
│                    └──────────────┘                                    │
│                          ↓                                            │
│                    ┌──────────────┐                                    │
│                    │  Border      │ ← SCION: 1-64514 → 1-64513       │
│                    │  Router      │     Host: fc00:10fc:200::2        │
│                    │  AS64513     │           → fc00:10fc:100::1      │
│                    │ 127.0.0.25  │                                    │
│                    └──────────────┘                                    │
│                          ↓                                            │
│   ┌──────────────────────────────────────────────────────────────┐   │
│   │                    SCION Topology                            │   │
│   │                                                               │   │
│   │     1-64512 (Core) ←──CHILD──→ 1-64513 (Server AS)          │   │
│   │                              ↕                                │   │
│   │                            PEER                               │   │
│   │                              ↓                                │   │
│   │                        1-64514 (Target AS)                   │   │
│   │                                                               │   │
│   └──────────────────────────────────────────────────────────────┘   │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

### Wichtige Punkte

1. **Client Namespace**: Hat keinen SCION - nur WireGuard Interface
2. **Server Namespace**: Enthält die SCION Topology mit AS64513, AS64514
3. **Translation**: Nur auf der Server-Seite (wg-server hat Translator)
4. **Border Router**: Nur AS64513 hat einen BR in der Topology

### Netzwerk Adressen

| Komponente | Adresse |
|------------|---------|
| Client WG | fd00::2 |
| Server WG | fd00::1 |
| Server SCION-mapped | fc00:10fc:100::1 |
| Client SCION-mapped | fc00:10fc:200::2 |
| AS64513 BR | 127.0.0.25:31006 |
| AS64514 BR | 127.0.0.33:31010 |

## Generated Packets

### Generated Packets

### IP Packets (`packets/ip/`)

#### `ip_client_to_server.bin`
- **Size**: 55 bytes
- **Source**: fd00::2 (WG client)
- **Destination**: fc00:10fc:100::1 (Server SCION-mapped, AS64513)
- **UDP**: 12345 → 30042
- **Payload**: "TEST123"

**Erklärung**: Das ist das IP Packet das vom Client kommt. Die Destination `fc00:10fc:100::1` ist eine SCION-mappable Address. Der Translator im wg-server wird das erkennen und zu SCION übersetzen.

#### `ip_server_to_client.bin`
- **Size**: 55 bytes  
- **Source**: fc00:10fc:100::1 (Server SCION-mapped, AS64513)
- **Destination**: fc00:10fc:200::2 (Client SCION-mapped, AS64514)
- **UDP**: 30042 → 12345
- **Payload**: "TEST123"

**Erklärung**: Das ist Return Traffic. Das kommt vom Server und soll zurück zum Client.

### SCION Packets (`packets/scion/`)

#### `scion_client_to_server.bin`
- **Size**: 239 bytes
- **Underlay**: IPv4/UDP
- **Source**: 10.0.0.1 → 127.0.0.25:31006 (AS64513 Border Router)
- **UDP**: 32766 → 31006
- **SCION Header**:
  - Src: 1-64514 (client AS - von SCION-mapped address abgeleitet)
  - Dst: 1-64513 (server AS)
  - Src Host: fc00:10fc:200::2
  - Dst Host: fc00:10fc:100::1

**Erklärung**: Das ist das Packet das nach der Translation rauskommt. Der Underlay zeigt auf AS64513's Border Router (127.0.0.25:31006).

#### `scion_server_to_client.bin`
- **Size**: 239 bytes
- **Underlay**: IPv4/UDP
- **Source**: 10.0.0.1 → 127.0.0.33:31010 (AS64514 Border Router)
- **UDP**: 32767 → 31010
- **SCION Header**:
  - Src: 1-64513 (server AS)
  - Dst: 1-64514 (client AS)
  - Src Host: fc00:10fc:100::1
  - Dst Host: fc00:10fc:200::2

**Erklärung**: Das ist das Return Packet. Der Underlay zeigt auf AS64514's Border Router (127.0.0.33:31010).

## Packet Flow

### Client → Server Direction (Translation)

```
Client Namespace:
  Client App → wg-client (fd00::2) → WireGuard Tunnel
                                                    ↓
Server Namespace:
  wg-server (fd00::1) ← WireGuard decrypt ← Tunnel
       ↓
  TUN Interface (IP Packet: fd00::2 → fc00:10fc:100::1)
       ↓
  Translator erkennt SCION-mapped Destination (fc00:10fc:100::1)
       ↓
  Translation: IP → SCION
       ↓
  SCION Packet (1-64514 → 1-64513)
       ↓
  Border Router AS64513 (127.0.0.25:31006)
       ↓
  SCION Topology → Weiterleitung
```

### Server → Client Direction (Return Traffic)

```
Server Namespace:
  SCION Topology → Border Router AS64514 (127.0.0.33:31010)
       ↓
  SCION Packet (1-64513 → 1-64514)
       ↓
  wg-server TUN
       ↓
  Keine Translation nötig? Oder SCION → IP?
       ↓
  WireGuard encrypt → Tunnel
                                                    ↓
Client Namespace:
  wg-client → Client App
```

## Validation

Run the validation script to verify packet structure:

```bash
cd /home/paul/Scintra/wireguard-go/testenvironment/packets
source /home/paul/Scintra/scapy-scion-int/.venv/bin/activate
python3 validate_packets.py
```

### Validating SCION Packet Through Topology

See [SCION_VALIDATION.md](./SCION_VALIDATION.md) for detailed instructions on:
- Sending SCION packets through the running topology
- Using scapy-scion-int to parse and verify packets
- Capturing packets at the Border Router
- Debugging SCION packet issues

Expected output:
```
============================================================
  Packet Validation
============================================================

=== Test 1: Client -> Server ===
[INFO] IP packet size: 55 bytes
[INFO] SCION packet size: 239 bytes
IP Packet: fd:00:00:00:00:00:00:00:00:00:00:00:00:00:00:02 -> fc:00:10:fc:01:00:00:00:00:00:00:00:00:00:00:01
[PASS] IP packet parsed
Underlay: 10.0.0.1 -> 127.0.0.25
[PASS] SCION packet parsed

=== Test 2: Server -> Client ===
[INFO] IP packet size: 55 bytes
[INFO] SCION packet size: 55 bytes
IP Packet: fc:00:10:fc:01:00:00:00:00:00:00:00:00:00:00:01 -> fc:00:10:fc:02:00:00:00:00:00:00:00:00:00:00:02
[PASS] IP packet parsed
Underlay: 10.0.0.1 -> 127.0.0.33
[PASS] SCION packet parsed

============================================================
[PASS] All packet validations passed!
============================================================
```

## Next Steps

1. **Validate SCION Packet**: Send the SCION packet through the running SCION topology and verify it's recognized as valid
2. **Test Integration**: Run the full integration test with WireGuard and SCION topology
3. **Capture at BR**: Use tcpdump or scapy-scion to capture packets at each stage

## Tool: scapy-scion-int

We use [scapy-scion-int](https://github.com/netsys-lab/scapy-scion-int) for SCION packet manipulation. Key usage:

```python
# Import SCION layers
from scapy_scion.layers.scion import SCION, SCIONPath, UDP

# Parse existing packet
pkt = Packet(scion_bytes)
if SCION in pkt:
    print(f"SCION: {pkt[SCION].src_isd}-{pkt[SCION].src_asn}")

# Create new SCION packet
scion = SCION(
    dst_isd=1,
    dst_asn="64513",
    src_isd=1, 
    src_asn="64514",
    dst_host="fc00:10fc:100::1",
    src_host="fc00:10fc:200::2"
) / UDP(sport=12345, dport=30042) / Raw(load=b"TEST")
```

## Files

| File | Description |
|------|-------------|
| `create_ip_packets.py` | Generate IPv6/UDP packets |
| `create_scion_packets.py` | Generate SCION packets |
| `validate_packets.py` | Validate packet structure |
| `SCION_VALIDATION.md` | Guide to test packets in SCION topology |
| `ip/*.bin` | IP packet binaries |
| `scion/*.bin` | SCION packet binaries |
