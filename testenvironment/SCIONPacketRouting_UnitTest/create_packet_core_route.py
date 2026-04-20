#!/usr/bin/env python3
"""
SCION Packet - Core Route WITH SCIONPath

Packet von AS64513 nach AS64514 ÜBER Core (AS64512)

Route:
  AS64513 ──► AS64512 ──► AS64514
   │         │
   │         └───► forwarded by BR automatically
   └─► Interface 1: 127.0.0.5 → 127.0.0.4
"""

import sys
import os
sys.path.insert(0, "/home/paul/Scintra/scapy-scion-int")

from scapy.all import Raw, wrpcap
from scapy.layers.inet import IP, UDP as ScapyUDP
from scapy_scion.layers.scion import SCION, SCIONPath, InfoField, HopField, EmptyPath
from datetime import datetime, timezone

# ==============================================================================
# KONFIGURATION
# ==============================================================================

# SCION Addresses
ISD = 1
SRC_ASN = 64513
DST_ASN = 64514

# SCION-mapped host addresses
SRC_HOST = "fc00:10fc:100::1"
DST_HOST = "fc00:10fc:200::1"

# Keys from gen/AS*/keys/master0.key
KEY_AS64513 = "mnGFG245QHwckTREBvt+uw=="
KEY_AS64514 = "3cnodzX08vGVseUeGytjQw=="
KEY_AS64512 = "1PzJOoXgRW4c0E7Jabd1TQ=="

# Underlay: Interface 1 (Parent Link to Core)
UNDERLAY_DST_IP = "127.0.0.4"
UNDERLAY_DST_PORT = 50000

# ==============================================================================
# ERKLÄRUNG: Core Route SCIONPath
# ==============================================================================

"""
═══════════════════════════════════════════════════════════════════════════════
CORE ROUTE: AS64513 → AS64512 → AS64514 (MIT SCIONPath)
═══════════════════════════════════════════════════════════════════════════════

Die Core Route erfordert 2 Segmente (up + down):

┌─────────────────────────────────────────────────────────────────────────────┐
│  Segment 0 (up): AS64513 → AS64512                              │
│  InfoField:                                                     │
│  ├── flags.C = 1 (constant)                                    │
│  └── timestamp = jetzt                                         │
│  HopField[0]:                                                  │
│  ├── cons_egress = 1  ← Interface 1 (zu AS64512)              │
│  └── MAC = (signiert mit AS64513 Key)                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  Segment 1 (down): AS64512 → AS64514                           │
│  InfoField:                                                     │
│  ├── flags.C = 1 (constant)                                    │
│  └── timestamp = jetzt                                         │
│  HopField[1]:                                                  │
│  ├── cons_ingress = 1  ← Interface 1 (von AS64513)            │
│  ├── cons_egress = 3   ← Interface 3 (zu AS64514)             │
│  └── MAC = (signiert mit AS64512 Key)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  HopField[2]:                                                  │
│  ├── cons_ingress = 3  ← Interface 3 (von AS64512)           │
│  └── MAC = (signiert mit AS64514 Key)                         │
└─────────────────────────────────────────────────────────────────────────────┘

Die Topology zeigt:
- AS64513 → AS64512: Interface 1 (parent)
- AS64512 → AS64514: Interface 3 (child)

Daher: 3 HopFields, nicht 2!
"""

# ==============================================================================
# PACKET ERSTELLUNG
# ==============================================================================

def create_scion_packet_core_route():
    """Erstellt SCION Packet MIT SCIONPath für Core Route."""
    
    print("=" * 70)
    print("Creating SCION Packet WITH SCIONPath: Core Route")
    print("=" * 70)
    print(f"Source AS:      1-{SRC_ASN}")
    print(f"Destination:   1-{DST_ASN}")
    print(f"Via:          {UNDERLAY_DST_IP}:{UNDERLAY_DST_PORT} (via AS64512)")
    print()
    print("Real route: AS64513 → AS64512 → AS64514")
    print("3 HopFields: AS64513.I1 → AS64512.I3 → AS64514.I3")
    print()
    print("Keys used:")
    print(f"  AS64513: {KEY_AS64513[:20]}...")
    print(f"  AS64512: {KEY_AS64512[:20]}...")
    print(f"  AS64514: {KEY_AS64514[:20]}...")
    
    # -------------------------------------------------------------------------
    # SCHRITT 1: InfoField(s) erstellen
    # -------------------------------------------------------------------------
    
    # Segment 0: AS64513 → AS64512 (up)
    info_field_0 = InfoField(
        flags=1,              # C=1 (constant), P=0
        segid=0,
        timestamp=datetime.now(tz=timezone.utc)
    )
    
    # Segment 1: AS64512 → AS64514 (down)
    info_field_1 = InfoField(
        flags=1,              # C=1 (constant), P=0
        segid=0,
        timestamp=datetime.now(tz=timezone.utc)
    )
    
    print("\n[SCHRITT 1: InfoFields]")
    print("  Segment 0 (up): AS64513 → AS64512")
    print(f"    flags.C: {info_field_0.flags.C}")
    print("  Segment 1 (down): AS64512 → AS64514")
    print(f"    flags.C: {info_field_1.flags.C}")
    
    # -------------------------------------------------------------------------
    # SCHRITT 2: HopField(s) erstellen
    # -------------------------------------------------------------------------
    
    # Hop 0: In AS64513, verlassen über Interface 1 (zu AS64512)
    hop_field_0 = HopField(
        flags=0,
        exp_time=1,
        cons_ingress=0,       # 0 = intra-AS (Start)
        cons_egress=1          # Interface 1 = zu AS64512
    )
    
    # Hop 1: In AS64512, Eingang Interface 1, Ausgang Interface 3
    hop_field_1 = HopField(
        flags=0,
        exp_time=1,
        cons_ingress=1,       # Interface 1 = von AS64513
        cons_egress=3          # Interface 3 = zu AS64514
    )
    
    # Hop 2: In AS64514, Eingang über Interface 3
    hop_field_2 = HopField(
        flags=0,
        exp_time=1,
        cons_ingress=3,       # Interface 3 = von AS64512
        cons_egress=0         # 0 = intra-AS (Ende)
    )
    
    print("\n[SCHRITT 2: HopFields]")
    print("  Hop 0 (in AS64513):")
    print(f"    cons_egress: {hop_field_0.cons_egress}  ← Interface 1 (zu AS64512)")
    print("  Hop 1 (in AS64512):")
    print(f"    cons_ingress: {hop_field_1.cons_ingress}  ← Interface 1")
    print(f"    cons_egress: {hop_field_1.cons_egress}  ← Interface 3 (zu AS64514)")
    print("  Hop 2 (in AS64514):")
    print(f"    cons_ingress: {hop_field_2.cons_ingress}  ← Interface 3")
    
    # -------------------------------------------------------------------------
    # SCHRITT 3: SCIONPath erstellen
    # -------------------------------------------------------------------------
    
    path = SCIONPath(
        seg0_len=1,              # HopField in Segment 0
        seg1_len=2,              # HopFields in Segment 1
        seg2_len=0,
        info_fields=[info_field_0, info_field_1],
        hop_fields=[hop_field_0, hop_field_1, hop_field_2]
    )
    
    print("\n[SCHRITT 3: SCIONPath erstellen]")
    print(f"  seg0_len: {path.seg0_len} (1 HopField)")
    print(f"  seg1_len: {path.seg1_len} (2 HopFields)")
    print(f"  seg2_len: {path.seg2_len}")
    print(f"  info_fields: {len(path.info_fields)}")
    print(f"  hop_fields: {len(path.hop_fields)}")
    
    # -------------------------------------------------------------------------
    # SCHRITT 4: MACs berechnen
    # -------------------------------------------------------------------------
    
    # Keys: für jeden HopField der Reihe nach
    # Hop0 braucht AS64513 Key, Hop1 braucht AS64512 Key, Hop2 braucht AS64514 Key
    keys = [KEY_AS64513, KEY_AS64512, KEY_AS64514]
    path.init_path(keys=keys)
    
    print("\n[SCHRITT 4: MACs berechnet mit AS Keys]")
    print(f"  Hop 0 MAC: {hop_field_0.mac:012x}")
    print(f"  Hop 1 MAC: {hop_field_1.mac:012x}")
    print(f"  Hop 2 MAC: {hop_field_2.mac:012x}")
    
    # -------------------------------------------------------------------------
    # SCHRITT 5: SCION Header
    # -------------------------------------------------------------------------
    
    scion = SCION(
        version=0,
        qos=0,
        fl=0,
        nh=17,              # Next Header = UDP
        ptype=1,            # Path Type = SCIONPath
        dt="IP",
        dl=3,
        st="IP",
        sl=3,
        
        dst_isd=ISD,
        dst_asn=DST_ASN,
        src_isd=ISD,
        src_asn=SRC_ASN,
        
        dst_host=DST_HOST,
        src_host=SRC_HOST,
        
        path=path
    )
    
    print("\n[SCHRITT 5: SCION Header]")
    print(f"  ptype:    {scion.ptype}  ← SCIONPath")
    print(f"  src:      {scion.src_isd}-{scion.src_asn} :: {scion.src_host}")
    print(f"  dst:      {scion.dst_isd}-{scion.dst_asn} :: {scion.dst_host}")
    
    # -------------------------------------------------------------------------
    # SCHRITT 6: Payload
    # -------------------------------------------------------------------------
    
    payload = ScapyUDP(sport=12345, dport=8080) / Raw(b"Core Route Test Packet with Path")
    print("\n[SCHRITT 6: Payload]")
    print(f"  UDP: {payload.sport} → {payload.dport}")
    
    packet = scion / payload
    print(f"\n[SCION PACKET TOTAL] {len(bytes(packet))} bytes")
    
    return packet


def create_complete_packet():
    """Erstellt komplettes Packet mit Underlay."""
    
    scion_packet = create_scion_packet_core_route()
    
    print("\n" + "=" * 70)
    print("Adding Underlay (IP/UDP)")
    print("=" * 70)
    
    complete_packet = IP(
        dst=UNDERLAY_DST_IP,
        src="127.0.0.1"
    ) / ScapyUDP(
        sport=50001,
        dport=UNDERLAY_DST_PORT
    ) / scion_packet
    
    print(f"  IP:   127.0.0.1 → {UNDERLAY_DST_IP}")
    print(f"  UDP:  50001 → {UNDERLAY_DST_PORT}")
    print(f"\n[COMPLETE PACKET] {len(bytes(complete_packet))} bytes")
    
    return complete_packet


def main():
    print("""
╔═══════════════════════════════════════════════════════════════════════╗
║  SCION Packet Creator - Core Route WITH SCIONPath                 ║
║  ───────────────────────────────────────────────────────────      ║
║  Route:  AS64513 → AS64512 → AS64514                             ║
║  Send TO: 127.0.0.4:50000                                     ║
║                                                                   ║
║  Path Type: SCIONPath (ptype=1)                                  ║
║  Segments: 2 (up + down)                                        ║
║  HopFields: 3                                                  ║
║  MACs: signiert mit AS Keys                                      ║
╚═══════════════════════════════════════════════════════════════════════╝
""")
    
    packet = create_complete_packet()
    
    print("\n" + "=" * 70)
    print("COMPLETE PACKET STRUCTURE")
    print("=" * 70)
    packet.show()
    
    print("\n[RAW BYTES]")
    packet_bytes = bytes(packet)
    print(f"Total: {len(packet_bytes)} bytes")
    print("Hex:   " + packet_bytes.hex())
    
    # Save
    output_file = "packet_core_route_with_path.pcap"
    wrpcap(output_file, [packet])
    print(f"\n[SAVED] {output_file}")
    
    print("\n" + "=" * 70)
    print("WAS PASSIERT BEIM SENDEN?")
    print("=" * 70)
    print("""
1. Packet geht an 127.0.0.4:50000 (BR von AS64512)
   
2. BR von AS64512 empfängt:
   → Sieht SCION Header mit dst_asn=64514
   → Sieht Path mit 3 HopFields
   
3. Path Verifizierung:
   → Liest HopField[1] (in AS64512)
   → Prüft MAC mit KEY_AS64512
   → ✓ MAC gültig!
   
4. AS64512 forwarded:
   → HopField[1].cons_egress = 3
   → Geht zu Interface 3 (127.0.0.9:50000)
   
5. BR von AS64514 empfängt:
   → Sieht dst_asn=64514
   → Prüft MAC von HopField[2] mit KEY_AS64514
   → ✓ MAC gültig!
   → delivered zu fc00:10fc:200::1
""")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())