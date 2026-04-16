# Step 1: Validate SCION Packet Routing Through Topology

## Overview

This step validates that our SCION packet can be sent through the SCION topology from AS64513 to AS64514.

## What We Test

1. **Packet Structure**: SCION packet is valid and parseable by scapy-scion-int
2. **First Hop**: Packet sent to AS64513 BR (127.0.0.25:31006)
3. **Topology Routing**: Packet captured at AS64514 BR (127.0.0.33:31010)

## Packet Details

```
File:           scion_AS64513_to_AS64514.bin
Source IA:      1-64513 (Server AS)
Dest IA:        1-64514 (Target AS)
Underlay IP:    10.0.0.1 -> 127.0.0.25:31006
Underlay UDP:   32766 -> 31006
SCION Host:     fc00:10fc:100::1 -> fc00:10fc:200::2
Payload:        TEST123
```

## Routing Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  SCION Packet: 1-64513 -> 1-64514                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Send to AS64513 BR                                             │
│     Underlay: 10.0.0.1 -> 127.0.0.25:31006                         │
│                                                                     │
│     ┌─────────────────┐                                            │
│     │  AS64513 BR     │                                            │
│     │  127.0.0.25     │                                            │
│     └────────┬────────┘                                            │
│              │                                                      │
│              │ SCION header says: dst=1-64514                      │
│              │                                                      │
│              ↓                                                      │
│     ┌─────────────────────────────────────┐                         │
│     │      SCION TOPOLOGY                 │                         │
│     │                                     │                         │
│     │   1-64512 (Core)                    │                         │
│     │       ↑                             │                         │
│     │     PEER (direct link)              │                         │
│     │       ↓                             │                         │
│     │   1-64513 ─────────── 1-64514      │                         │
│     │   (Server)          (Target)        │                         │
│     └─────────────────────────────────────┘                         │
│              │                                                      │
│              ↓                                                      │
│     ┌─────────────────┐                                            │
│     │  AS64514 BR     │                                            │
│     │  127.0.0.33     │                                            │
│     └─────────────────┘                                            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Commands Used

### Check (validate packet structure)

```bash
# Parse and validate SCION packet with scapy-scion-int
ip netns exec Server bash -c "
    source /home/paul/Scintra/scapy-scion-int/.venv/bin/activate
    python3 -c <parse_script>
"
```

### Send (test topology routing)

```bash
# Start capture at both BRs
ip netns exec Server tcpdump -i lo -nn port 31006 -c 3 -w /tmp/br_64513_capture.pcap &
ip netns exec Server tcpdump -i lo -nn port 31010 -c 3 -w /tmp/br_64514_capture.pcap &

# Send packet to AS64513 BR
ip netns exec Server bash -c "
    source /home/paul/Scintra/scapy-scion-int/.venv/bin/activate
    python3 -c <send_script>
"

# Show captures
ip netns exec Server tcpdump -r /tmp/br_64513_capture.pcap -nn
ip netns exec Server tcpdump -r /tmp/br_64514_capture.pcap -nn
```

## Usage

```bash
# Validate packet structure only
sudo ./01-validate-scion-packet.sh check

# Send packet through topology
sudo ./01-validate-scion-packet.sh send
```

## Expected Results

### Check Output
- Packet size: 239 bytes
- Underlay: 10.0.0.1 -> 127.0.0.25:31006
- SCION: 1-64513 -> 1-64514
- SCION Hosts: fc00:10fc:100::1 -> fc00:10fc:200::2

### Send Output
- Captured at AS64513 BR (31006): 3 packets received
- Captured at AS64514 BR (31010): 3 packets received + 1 response
- SUCCESS: Topology routing verified

## Files

- **Script**: `01-validate-scion-packet.sh`
- **Packet**: `packets/scion/scion_AS64513_to_AS64514.bin`
- **Generator**: `packets/create_scion_packets.py`

## Next Step

Step 2: IP packet from Client → translated to SCION (should produce same packet as scion_AS64513_to_AS64514.bin)