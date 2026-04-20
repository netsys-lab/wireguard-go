#!/usr/bin/env python3
"""
SCION Packet - Peer Link Route WITH SCIONPath

Packet von AS64513 nach AS64514 ÜBER Peer Link (DIREKT)

Route:
  AS64513 ───────────────────────────────► AS64514
           Send TO: 127.0.0.13:50000
           
           Interface 3: local=127.0.0.12 → remote=127.0.0.13
"""

import sys
import os
sys.path.insert(0, "/home/paul/Scintra/scapy-scion-int")

from scapy.all import Raw, wrpcap
from scapy.layers.inet import IP, UDP as ScapyUDP
from scapy_scion.layers.scion import SCION, SCIONPath, InfoField, HopField, EmptyPath

# ==============================================================================
# KONFIGURATION
# ==============================================================================

# SCION Addresses
ISD = 1
SRC_ASN = 64513      # AS number (decimal)
DST_ASN = 64514     # AS number (decimal)

# SCION-mapped host addresses
SRC_HOST = "fc00:10fc:100::1"
DST_HOST = "fc00:10fc:200::1"

# Keys from gen/AS*/keys/master0.key
KEY_AS64513 = "mnGFG245QHwckTREBvt+uw=="
KEY_AS64514 = "3cnodzX08vGVseUeGytjQw=="

# Underlay: Interface 3 (Peer Link)
UNDERLAY_DST_IP = "127.0.0.13"
UNDERLAY_DST_PORT = 50000

# ==============================================================================
# ERKLÄRUNG: SCIONPath vs EmptyPath
# ==============================================================================

"""
═══════════════════════════════════════════════════════════════════════════════
SCIONPath STRUKTUR
═══════════════════════════════════════════════════════════════════════════════

SCIONPath besteht aus:
1. PathMeta Header (8 bytes)
2. InfoField(s) - Segment-Informationen  
3. HopField(s) - Hop-Informationen mit MAC

┌─────────────────────────────────────────────────────────────────────────────┐
│  PathMeta Header:                                                          │
│  ├── curr_inf    = Welches InfoField aktuell verwendet                   │
│  ├── curr_hf     = Welcher HopField aktuell                              │
│  ├── seg0_len   = Anzahl HopFields in Segment 0                         │
│  ├── seg1_len   = Anzahl HopFields in Segment 1                         │
│  └── seg2_len   = Anzahl HopFields in Segment 2                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  InfoField (für jedes Segment):                                           │
│  ├── flags.C    = Constancy Flag (Segment unveränderlich)               │
│  ├── flags.P    = Peering Flag                                           │
│  ├── segid      = Segment ID                                             │
│  └── timestamp  = Gültigkeitszeitraum                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  HopField (für jeden Hop):                                                │
│  ├── flags.E    = Egress Flag                                           │
│  ├── flags.I    = Ingress Flag                                          │
│  ├── exp_time   = Ablaufzeit (in 24h/256 Einheiten)                    │
│  ├── cons_ingress = Ingress Interface ID                                │
│  ├── cons_egress  = Egress Interface ID                                 │
│  └── mac        = Message Authentication Code (von AS Key signiert)    │
└─────────────────────────────────────────────────────────────────────────────┘

FÜR PEER LINK TEST:
═══════════════════════════════════════════════════════════════════════════════

Unser Path für Peer Link (AS64513 → AS64514):

┌─────────────────────────────────────────────────────────────────────────────┐
│  Segment 0 (up segment): AS64513 → AS64514                               │
│                                                                           │
│  InfoField:                                                               │
│  ├── flags.C = 0 (nicht constant, kann erweitert werden)                │
│  ├── flags.P = 0 (kein peering)                                         │
│  ├── segid   = (wird von MAC abgeleitet)                                │
│  └── timestamp = jetzt                                                   │
│                                                                           │
│  HopField 0 (in AS64513):                                                │
│  ├── cons_egress = 3   ← Interface ID 3 (unser Ausgang)               │
│  └── mac         = (signiert mit KEY_AS64513)                           │
│                                                                           │
│  HopField 1 (in AS64514):                                                │
│  ├── cons_ingress = 3   ← Interface ID 3 (bei AS64514)                │
│  └── mac         = (signiert mit KEY_AS64514)                          │
└─────────────────────────────────────────────────────────────────────────────┘

Der MAC wird mit dem AS Master Key berechnet und verifiziert dass:
- Das Packet确实是 von der AS kommt
- Das Packet nicht manipuliert wurde
- Das Packet über das angegebene Interface geht
"""

# ==============================================================================
# PACKET ERSTELLUNG MIT SCIONPath
# ==============================================================================

def create_scion_packet_with_path():
    """
    Erstellt SCION Packet MIT korrektem SCIONPath.
    
    Dieser Path enthält:
    - 1 InfoField (für Segment)
    - 2 HopFields (einer für jeden Hop)
    - MACs signiert mit den AS Keys
    """
    
    print("=" * 70)
    print("Creating SCION Packet WITH SCIONPath: Peer Link Route")
    print("=" * 70)
    print(f"Source AS:      1-{SRC_ASN}")
    print(f"Destination:   1-{DST_ASN}")
    print(f"Via:          {UNDERLAY_DST_IP}:{UNDERLAY_DST_PORT} (Peer Link)")
    print()
    print("Keys used:")
    print(f"  AS64513: {KEY_AS64513[:20]}...")
    print(f"  AS64514: {KEY_AS64514[:20]}...")
    
    # -------------------------------------------------------------------------
    # SCHRITT 1: InfoField erstellen
    # -------------------------------------------------------------------------
    # InfoField enthält Segment-Informationen
    
    from datetime import datetime, timezone, timedelta
    
    info_field = InfoField(
        flags=0,          # Kein Constancy Flag, kein Peering Flag
        segid=0,          # Wird später von MAC abgeleitet
        timestamp=datetime.now(tz=timezone.utc)  # Jetzt
    )
    
    print("\n[SCHRIT 1: InfoField]")
    print(f"  flags:     {info_field.flags}")
    print(f"  timestamp: {info_field.timestamp}")
    print("  → Beschreibt das Path-Segment")
    
    # -------------------------------------------------------------------------
    # SCHRITT 2: HopField(s) erstellen
    # -------------------------------------------------------------------------
    # HopField enthält:
    # - cons_ingress: Interface ID für Eingang
    # - cons_egress: Interface ID für Ausgang  
    # - mac: Signatur
    
    # Hop 0: In AS64513, verlassen über Interface 3
    hop_field_0 = HopField(
        flags=0,              # Keine speziellen Flags
        exp_time=1,          # Läuft ab nach ~1 Tag
        cons_ingress=0,      # Eingang (0 = intra-AS)
        cons_egress=3        # Ausgang = Interface 3 (zu AS64514)
    )
    
    # Hop 1: In AS64514, Eingang über Interface 3
    hop_field_1 = HopField(
        flags=0,
        exp_time=1,
        cons_ingress=3,      # Eingang = Interface 3 (von AS64513)
        cons_egress=0        # Ausgang (0 = intra-AS)
    )
    
    print("\n[SCHRITT 2: HopFields]")
    print("  Hop 0 (in AS64513):")
    print(f"    cons_egress: {hop_field_0.cons_egress}  ← Interface 3")
    print(f"    cons_ingress: {hop_field_0.cons_ingress}")
    print("  Hop 1 (in AS64514):")
    print(f"    cons_ingress: {hop_field_1.cons_ingress}  ← Interface 3")
    print(f"    cons_egress:  {hop_field_1.cons_egress}")
    
    # -------------------------------------------------------------------------
    # SCHRITT 3: SCIONPath erstellen und mit Keys signieren
    # -------------------------------------------------------------------------
    
    path = SCIONPath(
        seg0_len=2,              # 2 HopFields in Segment 0
        seg1_len=0,              # Kein Segment 1
        seg2_len=0,              # Kein Segment 2
        info_fields=[info_field],
        hop_fields=[hop_field_0, hop_field_1]
    )
    
    print("\n[SCHRITT 3: SCIONPath erstellen]")
    print(f"  seg0_len: {path.seg0_len} (2 HopFields)")
    print(f"  info_fields: {len(path.info_fields)}")
    print(f"  hop_fields: {len(path.hop_fields)}")
    
    # -------------------------------------------------------------------------
    # SCHRITT 4: MACs berechnen mit AS Keys
    # -------------------------------------------------------------------------
    # Die MACs werden mit dem AS Master Key berechnet
    # Format: base64 key
    
    # WICHTIG: Die Keys müssen in der Reihenfolge der Hops sein!
    # Für Segment 0: AS64513 Key für Hop 0, AS64514 Key für Hop 1
    
    keys = [KEY_AS64513, KEY_AS64514]  # Keys für jeden Hop
    
    path.init_path(keys=keys)
    
    print("\n[SCHRITT 4: MACs berechnet mit AS Keys]")
    print(f"  Hop 0 MAC: {hop_field_0.mac:012x}")
    print(f"  Hop 1 MAC: {hop_field_1.mac:012x}")
    print("  → Diese MACs verifizieren dass das Packet legitim ist")
    
    # -------------------------------------------------------------------------
    # SCHRITT 5: SCION Header mit SCIONPath
    # -------------------------------------------------------------------------
    
    scion = SCION(
        version=0,
        qos=0,
        fl=0,
        nh=17,              # Next header = UDP
        ptype=1,            # ← Path Type = SCIONPath (NICHT EmptyPath!)
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
        
        path=path           # ← Unser SCIONPath mit HopFields
    )
    
    print("\n[SCHRITT 5: SCION Header]")
    print(f"  ptype:    {scion.ptype}  ← SCIONPath (NICHT Empty!)")
    print(f"  src:      {scion.src_isd}-{scion.src_asn} :: {scion.src_host}")
    print(f"  dst:      {scion.dst_isd}-{scion.dst_asn} :: {scion.dst_host}")
    
    # -------------------------------------------------------------------------
    # SCHRITT 6: UDP Payload
    # -------------------------------------------------------------------------
    
    payload = ScapyUDP(sport=12345, dport=8080) / Raw(b"Peer Link Test Packet with Path")
    print("\n[SCHRITT 6: Payload]")
    print(f"  UDP: {payload.sport} → {payload.dport}")
    
    # Combine
    packet = scion / payload
    print(f"\n[SCION PACKET TOTAL] {len(bytes(packet))} bytes")
    
    return packet


def create_complete_packet():
    """Erstellt komplettes Packet mit Underlay."""
    
    scion_packet = create_scion_packet_with_path()
    
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
║  SCION Packet Creator - Peer Link Route WITH SCIONPath               ║
║  ─────────────────────────────────────────────────────────────────── ║
║  Route:  AS64513 → AS64514 (direkt via Peer Link)                    ║
║  Send TO: 127.0.0.13:50000                                           ║
║                                                                           ║
║  Path Type: SCIONPath (ptype=1)                                        ║
║  HopFields: 2 (einer für AS64513, einer für AS64514)                 ║
║  MACs: signiert mit AS Master Keys                                    ║
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
    output_file = "packet_peer_link_with_path.pcap"
    wrpcap(output_file, [packet])
    print(f"\n[SAVED] {output_file}")
    
    print("\n" + "=" * 70)
    print("WAS PASSIERT BEIM SENDEN?")
    print("=" * 70)
    print("""
1. Packet geht an 127.0.0.13:50000 (BR von AS64514)
   
2. BR von AS64514 empfängt:
   → Sieht SCION Header mit dst_asn=64514
   → Sieht Path mit HopFields
   → Prüft MAC von HopField[1] mit AS64514 Key
   → ✓ MAC gültig!
   
3. BR von AS64514:
   → Sieht cons_ingress=3 (Interface 3)
   → Forwarded zu local host fc00:10fc:200::1
""")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())