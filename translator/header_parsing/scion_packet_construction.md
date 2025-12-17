# SCION Packet Construction & Manual UDP Checksum
_A polished guide for building SCION packets in Go_

---

## 📘 Overview

This document explains how to construct a **fully valid SCION packet** in Go, including:

- Building SCION headers (`slayers.SCION`)
- Embedding L4 headers (UDP/TCP)
- Creating correct SCION host addresses (IPv4 & IPv6)
- Injecting SCION paths (`snet.Path`)
- Manually computing SCION UDP checksums (required!)
- Final serialization into on-wire SCION bytes

It is specifically tailored for implementations like the WireGuard SCION Translator.

---

## 🧱 SCION Packet Structure

A SCION packet consists of three major components:

```
+-------------------------------+
| SCION Common Header           |
+-------------------------------+
| SCION Address Header          |
+-------------------------------+
| SCION Path Header             |
+-------------------------------+
| L4 Header (UDP/TCP/SCMP)      |
+-------------------------------+
| Application Payload           |
+-------------------------------+
```

When SCION is transported over an IPv4 or IPv6 underlay (as WireGuard does):

```
+-------------------------------+
| IPv4 / IPv6 Underlay Header   |
+-------------------------------+
| UDP Underlay Header           |
+-------------------------------+
| Embedded SCION Packet         |
+-------------------------------+
```

---

## 🏗️ Constructing the SCION Header

Create a SCION header using `slayers.SCION`:

```go
pkt := &slayers.SCION{
    Version:      slayers.SCIONVersion,
    TrafficClass: tc,      // optionally from outer IPv6
    FlowID:       flowID,  // typically derived from IPv6 FlowLabel
    NextHdr:      nextHeader, // L4 protocol: slayers.L4UDP or slayers.L4TCP
    SrcIA:        srcIA,
    DstIA:        dstIA,
}
```

### Setting SCION Host Addresses

Host addresses must be represented as:

```
addr.HostIP(netip.Addr)
```

Example:

```go
srcNetip, _ := netip.ParseAddr("10.0.0.1")
dstNetip, _ := netip.ParseAddr("10.0.0.2")

pkt.SetSrcAddr(addr.HostIP(srcNetip))
pkt.SetDstAddr(addr.HostIP(dstNetip))
```

SCION will automatically choose:
- **T4Ip** for IPv4 hosts  
- **T16Ip** for IPv6 hosts  

---

## 🛣️ Adding the SCION Path

To embed a SCION forwarding path:

```go
dp := path.Dataplane()
dp.SetPath(pkt)
```

This attaches the compressed SCION path into the packet.

---

## 🔌 Adding the L4 Header (UDP/TCP)

UDP is handled using the standard `layers.UDP`:

```go
innerUDP := &layers.UDP{
    SrcPort: udpSrc,
    DstPort: udpDst,
}
```

⚠️ **SCION DOES NOT provide a `slayers.UDP` or `slayers.TCP`.**  
Use `layers.UDP` and `layers.TCP`.

---

## ❗ Why manual UDP checksums are required

### Problem:
`gopacket` cannot compute checksums when the network layer is **SCION**.

`SetNetworkLayerForChecksum()` only supports:
- IPv4
- IPv6

So checksum computation fails.

### Solution:
Compute the UDP checksum **manually** using the SCION pseudo-header.

---

# 📐 SCION UDP Pseudo-Header Format

The SCION UDP checksum is computed over:

```
pseudo_header || udp_header || payload
```

### Pseudo-header format:

| Field | Size |
|-------|------|
| DstISD | 2 |
| DstAS | 4 |
| SrcISD | 2 |
| SrcAS | 4 |
| DstHostAddr | 4 or 16 |
| SrcHostAddr | 4 or 16 |
| UpperLen | 4 |
| Zeros | 3 |
| NextHeader | 1 |

### Total pseudo-header size:

| Host Type | Size |
|----------|-------|
| IPv4 | 28 bytes |
| IPv6 | 52 bytes |

---

# 🧮 Manual Checksum Algorithm

SCION uses the standard 16‑bit one’s‑complement checksum:

```
checksum = ~ones_complement_sum( pseudo || udp || payload )
```

Algorithm steps:

1. Set `UDP.Checksum = 0`
2. Build SCION pseudo-header
3. Serialize the UDP header without checksum
4. Concatenate:  
   `PH || UDP_HDR || PAYLOAD`
5. Compute one's complement checksum
6. Write it back into the UDP header

---

# 🔎 Example (IPv4 Hosts)

Given:
- SrcIA: `1-64496`
- DstIA: `2-64497`
- SrcHost: `10.0.0.1`
- DstHost: `10.0.0.2`
- UDP payload: `"TEST"` (4 bytes)
- Ports: `32766 → 31002`

Pseudo-header:

```
00 01         DstISD
00 00 FC F1   DstAS
00 01         SrcISD
00 00 FC F0   SrcAS
0A 00 00 02   DstHost
0A 00 00 01   SrcHost
00 00 00 0C   UpperLen = 12
00 00 00 11   NextHdr = UDP
```

Checksum:

```
udp.Checksum = ~sum16(pseudo || udp_no_cksum || "TEST")
```

---

# 🧰 Essential Code Snippets

## Pseudo Header Builder

```go
func buildSCIONUDPPseudoHeader(
    srcIA, dstIA addr.IA,
    srcHost, dstHost net.IP,
    upperLen uint16,
    nextHdr slayers.L4ProtocolType,
) ([]byte, error) {
    ...
}
```

## Checksum Function

```go
func checksum16(data []byte) uint16 {
    var sum uint32
    for i := 0; i+1 < len(data); i += 2 {
        sum += uint32(binary.BigEndian.Uint16(data[i:]))
    }
    if len(data)%2 == 1 {
        sum += uint32(data[len(data)-1]) << 8
    }
    for (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return ^uint16(sum)
}
```

## Manual UDP Checksum Application

```go
switch udp := l4layer.(type) {
case *layers.UDP:
    upperLen := uint16(8 + len(l4Payload))
    udp.Length = upperLen
    udp.Checksum = 0

    // Serialize UDP header without checksum
    ubuf := gopacket.NewSerializeBuffer()
    udp.SerializeTo(ubuf, gopacket.SerializeOptions{
        FixLengths: true,
        ComputeChecksums: false,
    })

    udpBytes := ubuf.Bytes()

    pseudo, _ := buildSCIONUDPPseudoHeader(
        srcIA, dstIA, srcHost, dstHost, upperLen, nextHeader,
    )

    buf := append(append(pseudo, udpBytes...), l4Payload...)
    udp.Checksum = checksum16(buf)
}
```

---

# 🛠️ Troubleshooting Checksum Mismatches

| Issue | Description |
|-------|-------------|
| Wrong host length | IPv6 must use 16‑byte host addresses |
| Wrong UpperLen | Must be `UDPHeader(8) + payload` |
| Wrong NextHdr | Must match `slayers.L4UDP` (= 17) |
| UDP.Checksum not zero before calculation | Produces invalid sum |
| Odd-length data | Must pad with zero byte |

To debug:

```go
fmt.Printf("Pseudo: %x
", pseudo)
fmt.Printf("UDP: %x
", udpBytes)
fmt.Printf("Payload: %x
", l4Payload)
fmt.Printf("Checksum input: %x
", buf)
fmt.Printf("Checksum = %04x
", udp.Checksum)
```


