# Packet Flow Validation

This document explains the validation script that proves the SCION-WireGuard packet flow works correctly.

## Overview

This validation script (`PacketFlow_From_Client_To_BR.sh`) proves packets flow correctly from the Client namespace through WireGuard to the SCION Border Router. It validates the first milestone: **Client → WireGuard → SCION Translation → Border Router**.

## Quick Start

```bash
cd /home/paul/Scintra/wireguard-go/testenv
sudo ./PacketFlow_From_Client_To_BR.sh validate
```

## Validation Stages

### Stage 1: WG Server Interface

**Purpose:** Prove packets arrive at the WG server interface from the WireGuard tunnel.

**How it works:**
1. Find the WireGuard interface in Server namespace (`wg-server`)
2. Start tcpdump in background, writing to pcap file
3. Send 3 UDP test packets from Client namespace to SCION-mapped address (`fc00:10fc:200::2:30042`)
4. Stop tcpdump, read and analyze the pcap file

**What it proves:**
```
11:10:47.619674 IP 10.0.0.2.30041 > 127.0.0.25.31006: UDP, length 118
```

| Field | Value | Meaning |
|-------|-------|---------|
| Source | 10.0.0.2:30041 | Client (underlay IP + SCION port) |
| Destination | 127.0.0.25:31006 | AS64513 Border Router |

This confirms:
- Packet exited the WireGuard tunnel at the server side
- Packet was translated to SCION format
- Destination is the AS64513 Border Router

---

### Stage 2: AS64513 Border Router

**Purpose:** Prove packets reach the AS64513 Border Router on port 31006.

**How it works:**
1. Send test packet from Client namespace
2. Capture on loopback interface filtering for port 31006
3. Check if packets were captured

**What it proves:**
```
11:11:00.871183 IP 127.0.0.25.31006 > 10.0.0.1.31004: UDP, length 76
```

This confirms:
- WG Server (10.0.0.1) sent packet to BR at 127.0.0.25:31006
- Packet reached the SCION infrastructure
- BR processed the packet (response visible in capture)

---

### Stage 3: SCION Packet Structure

**Purpose:** Validate the SCION packet format (UDP encapsulation).

**How it works:**
1. Capture packet on loopback with hex output (`-x`)
2. Analyze the raw bytes to verify:
   - SCION version = 0 (first nibble in payload)
   - UDP encapsulation present

**What it proves (hex analysis):**
```
0x0000:  4500 056c 3501 4000 4011 7766 0a00 0001
0x0010:  7f00 0019 7fff 791e 0558 8e83 0000 0001
...
```

- Outer: IPv4/UDP header (first 2 lines)
- Inner: SCION packet with proper header structure
- UDP encapsulation detected

## Command Reference

### Full Validation

```bash
sudo ./PacketFlow_From_Client_To_BR.sh validate
```

Runs all 3 stages and provides a summary.

### Individual Stages

```bash
# Stage 1: WG Interface only
sudo ./PacketFlow_From_Client_To_BR.sh stage1

# Stage 2: AS64513 BR only  
sudo ./PacketFlow_From_Client_To_BR.sh stage2

# Stage 3: SCION Structure only
sudo ./PacketFlow_From_Client_To_BR.sh stage3
```

## Output Example

```
========================================
  SCION-WireGuard Packet Validation
  Using tcpdump for packet capture
========================================

[INFO] === Stage 1: WG Server Interface ===
[INFO] Capturing on interface: wg-server
[INFO] Sending test packet from client...
[PASS] Captured 3 packets on WG interface

Packet details:
11:10:47.619674 IP 10.0.0.2.30041 > 127.0.0.25.31006: UDP, length 118

[INFO] === Stage 2: AS64513 Border Router (port 31006) ===
[PASS] AS64513 BR received 3 packets

[INFO] === Stage 3: SCION Packet Structure ===
[PASS] ✓ UDP encapsulation detected

========================================
  Summary: 3 passed, 0 failed
========================================
✓ Packet flow validated!

Proof:
  1. Client sends IP packet with SCION-mapped dst
  2. WG Client translates to SCION packet
  3. WG Server interface receives encapsulated packet
  4. Packet routed to AS64513 BR at 127.0.0.25:31006
  5. Valid SCION structure confirmed
```

## What This Validates

This validation proves the **first milestone**:

```
Client → WireGuard → SCION Translation → Border Router ✓
```

### What Works:
- ✓ Client sends IP packet with SCION-mapped destination
- ✓ WireGuard Client detects SCION-mapped address
- ✓ Translation from IP → SCION happens
- ✓ Packet goes through WireGuard tunnel
- ✓ Server receives packet
- ✓ Server routes packet to AS64513 Border Router
- ✓ Valid SCION structure confirmed

### What Remains Untested:
- ✗ SCION inter-AS routing (AS64513 → AS64514)
- ✗ Echo server delivery
- ✗ Return path (SCION → IP translation)

## Troubleshooting

### Stage 1 fails: No packets on WG interface

**Symptoms:** `No packets captured on WG interface`

**Possible causes:**
1. WireGuard not connected (check `wg show`)
2. Path retrieval failing (check client logs)
3. Translation error (check wg-client.log for errors)

**Debug:**
```bash
# Check WireGuard status
sudo wg show

# Check client logs for translation errors
tail -f logs/wg-client.log | grep -i error

# Manual capture
sudo ip netns exec Server tcpdump -i wg-server -nn
```

### Stage 2 fails: No packets at BR

**Symptoms:** `No packets at AS64513 BR`

**Possible causes:**
1. Routing not configured on server
2. SCION not running
3. Kernel not forwarding to loopback

**Debug:**
```bash
# Check SCION is running
cd /home/paul/Scintra/scion
./scion.sh status

# Check routing
sudo ip netns exec Server ip route
```

## How It Works

### Packet Flow

```
Client Namespace                    Server Namespace
┌─────────────────┐               ┌─────────────────┐
│  nc -u         │               │  wg-server      │
│  fc00:...::2   │──────UDP─────►│  (TUN)          │
│  :30042        │  WireGuard    │                 │
└─────────────────┘    Tunnel     └────────┬────────┘
                                          │
                                          ▼ (decrypts, writes to TUN)
                                    Kernel routing
                                          │
                                          ▼ (via loopback)
                                 ┌─────────────────┐
                                 │  BR port 31006  │
                                 │  127.0.0.25     │
                                 └─────────────────┘
```

### Test Packet Generation

The script sends UDP packets to a SCION-mapped address:
- **Destination:** `fc00:10fc:200::2:30042`
  - `fc00:10fc:200::` = AS64514 SCION prefix
  - `2` = host identifier
  - `30042` = echo server port
- **Why UDP:** SCION uses UDP as underlay transport

### Capture Strategy

| Stage | Interface | Filter | Why |
|-------|-----------|--------|-----|
| 1 | wg-server | udp | Catch packets exiting tunnel |
| 2 | lo | port 31006 | Catch packets to BR |
| 3 | lo | port 31006 | Analyze raw packet structure |

## Files

| File | Purpose |
|------|---------|
| `PacketFlow_From_Client_To_BR.sh` | Main validation script |
| `logs/tcpdump-wg-server.pcap` | Stage 1 capture file |
| `logs/tcpdump-scion-raw.pcap` | Stage 3 capture file |

## Related Documentation

- [TEST_VERIFICATION_GUIDE.md](./TEST_VERIFICATION_GUIDE.md) - Full test verification guide
- [Plan.md](./Plan.md) - Original test plan
- [translation-architecture.md](../docs/translation-architecture.md) - Translation architecture
