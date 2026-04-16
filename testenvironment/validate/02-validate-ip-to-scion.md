# Step 2: Validate IP to SCION Translation

## Overview

This step validates that an IP packet sent from the Client namespace is correctly translated to a SCION packet matching our expected `scion_AS64513_to_AS64514.bin`.

## What We Test

1. **IP Packet**: Sent from Client (fd00::2) to AS64514 SCION-mapped address (fc00:10fc:200::2)
2. **Translation**: Packet gets translated to SCION (1-64513 -> 1-64514)
3. **Verification**: Compare captured packet with expected SCION packet

## Packet Mapping

### Input: IP Packet (ip_AS64513_to_AS64514.bin)

```
Source:      fd00::2 (Client WG interface)
Dest:        fc00:10fc:200::2 (AS64514 SCION-mapped address)
UDP:         12345 -> 30042
Payload:     TEST123
```

### After Translation: SCION (should match scion_AS64513_to_AS64514.bin)

```
Source IA:   1-64513 (Server AS - where WG server is)
Dest IA:     1-64514 (Target AS)
Underlay:    10.0.0.1 -> 127.0.0.25:31006 (AS64513 BR)
SCION Host:  fc00:10fc:100::1 -> fc00:10fc:200::2
Payload:     TEST123
```

## Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  Client Namespace                                                  │
│                                                                     │
│  ┌──────────┐                                                       │
│  │ wg-client│  fd00::2                                            │
│  └────┬─────┘                                                       │
│       │ IP Packet: fd00::2 -> fc00:10fc:200::2                     │
│       │ UDP: 12345 -> 30042                                        │
│       ↓                                                             │
└───────╦──────────────────────────────────────────────────────────────
        ║ WireGuard Tunnel
        ↓
┌───────────────────────────────────────────────────────────────────────┐
│  Server Namespace                                                   │
│                                                                       │
│  ┌──────────┐                                                       │
│  │ wg-server│  fd00::1                                              │
│  └────┬─────┘                                                       │
│       │ Packet arrives, decrypted                                   │
│       ↓                                                             │
│  ┌─────────────────────────────────────────┐                        │
│  │ Translator                               │                        │
│  │  - Detects SCION-mapped dest            │                        │
│  │  - Maps: fd00::2 -> AS64513 (server)    │                        │
│  │  - Maps: fc00:10fc:200::2 -> AS64514    │                        │
│  │  - Creates SCION packet                 │                        │
│  └────────────────────┬────────────────────┘                        │
│                       │ SCION: 1-64513 -> 1-64514                     │
│                       ↓                                               │
│  ┌─────────────────────────────────────────┐                        │
│  │ Border Router AS64513 (127.0.0.25:31006)│                        │
│  └─────────────────────────────────────────┘                        │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

## Commands Used

### Send IP packet from Client

```bash
# Capture at Server TUN
ip netns exec Server tcpdump -i wg-server -nn -w /tmp/ip_capture.pcap &

# Capture at BR
ip netns exec Server tcpdump -i lo -nn port 31006 -c 1 -w /tmp/br_capture.pcap &

# Send IP packet from Client
ip netns exec Client bash -c "
    source /home/paul/Scintra/scapy-scion-int/.venv/bin/activate
    python3 -c \"
from scapy.all import *
send(IPv6(src='fd00::2', dst='fc00:10fc:200::2')/UDP(sport=12345, dport=30042)/'TEST123')
\"
"
```

### Compare captured vs expected

```bash
# Show expected SCION packet
xxd packets/scion/scion_AS64513_to_AS64514.bin | head

# Show captured packet
ip netns exec Server tcpdump -r /tmp/br_capture.pcap -X -vv
```

## Usage

```bash
# Send IP packet from Client and verify translation
sudo ./02-validate-ip-to-scion.sh send

# Compare captured packet with expected SCION
sudo ./02-validate-ip-to-scion.sh compare
```

## Expected Results

### Send Output
- IP packet captured at Client TUN
- Translated SCION packet captured at Server TUN
- SCION packet captured at AS64513 BR (127.0.0.25:31006)

### Compare
- Captured SCION should match: scion_AS64513_to_AS64514.bin
- Underlay: 10.0.0.1 -> 127.0.0.25:31006
- SCION: 1-64513 -> 1-64514
- Host: fc00:10fc:100::1 -> fc00:10fc:200::2

## Files

- **Script**: `02-validate-ip-to-scion.sh`
- **IP Packet**: `packets/ip/ip_AS64513_to_AS64514.bin`
- **Expected SCION**: `packets/scion/scion_AS64513_to_AS64514.bin`

## Captured Packets

After running `sudo ./02-validate-ip-to-scion.sh send`, captures are saved to:

```
testenvironment/captures/
├── step2_server_tun_capture.pcap    # Packet at Server TUN (translated SCION)
└── step2_br_64513_capture.pcap      # Packet at AS64513 BR
```

View captures with payload:
```bash
# Using the read script
sudo ./read_capture.sh step2_server_tun_capture.pcap

# Or directly with tcpdump
tcpdump -r testenvironment/captures/step2_server_tun_capture.pcap -X
```

## Previous Step

- **Step 1**: Validate SCION packet routing through topology (AS64513 -> AS64514)

## Next Step

- **Step 3**: Verify packet transfer from WG Server Interface to AS64513 BR