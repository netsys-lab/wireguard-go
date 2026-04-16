#!/usr/bin/env python3
"""
Generate SCION test packets for the integration test environment.
Creates SCION packets that correspond to the translated IP packets.

Usage:
    sudo python3 create_scion_packets.py

The packets are saved to testenvironment/packets/scion/
"""

import sys
import os
import struct

sys.path.insert(0, '/home/paul/Scintra/scapy-scion-int')

from scapy.layers.inet import IP, UDP
from scapy_scion.layers.scion import SCION, SCIONPath, InfoField, HopField
from scapy.all import Raw
from datetime import datetime

# Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
BLUE = '\033[0;34m'
NC = '\033[0m'

def log_info(msg):
    print(f"{BLUE}[INFO]{NC} {msg}")

def log_success(msg):
    print(f"{GREEN}[OK]{NC} {msg}")

# Topology configuration (from testenvironment/config.sh)
SCION_LOCAL_IA = "1-64513"  # Server AS
SCION_REMOTE_IA = "1-64514"  # Client AS

# SCION addresses
# AS64513: fc00:10fc:100::/64 (BR internal_addr: [fc00:10fc:100::]:31006)
# AS64514: fc00:10fc:200::/64 (BR internal_addr: [fc00:10fc:200::]:31010)
SCION_SERVER_ADDR = "fc00:10fc:100::1"  # Server SCION-mapped (AS64513)
SCION_CLIENT_ADDR = "fc00:10fc:200::2"  # Client SCION-mapped (AS64514)

# Underlay addresses (from topology)
# AS64513 BR: 127.0.0.25:31006
# AS64514 BR: 127.0.0.33:31010
UNDERLAY_SERVER = "127.0.0.25"  # Server AS BR
UNDERLAY_CLIENT = "127.0.0.33"  # Client AS BR

BR_PORT = 31006  # Border router port

# Test payload
PAYLOAD = b"TEST123"

# Output directory
OUTPUT_DIR = "/home/paul/Scintra/wireguard-go/testenvironment/packets/scion"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def create_scion_path():
    """Create a SCION path for testing"""
    path = SCIONPath(
        curr_inf=2,
        curr_hf=8,
        seg0_len=3,
        seg1_len=2,
        seg2_len=4,
        info_fields=[
            InfoField(flags="", segid=1,
                timestamp=datetime.fromisoformat("2025-03-25T12:00:00Z")),
            InfoField(flags="C", segid=2,
                timestamp=datetime.fromisoformat("2025-03-25T13:00:00Z")),
            InfoField(flags="C", segid=3,
                timestamp=datetime.fromisoformat("2025-03-25T14:00:00Z")),
        ],
        hop_fields=[
            HopField(cons_ingress=4, cons_egress=0),
            HopField(cons_ingress=2, cons_egress=3),
            HopField(cons_ingress=0, cons_egress=1),
            HopField(cons_ingress=0, cons_egress=5),
            HopField(cons_ingress=6, cons_egress=0),
            HopField(cons_ingress=0, cons_egress=7),
            HopField(cons_ingress=8, cons_egress=9),
            HopField(cons_ingress=10, cons_egress=11),
            HopField(cons_ingress=12, cons_egress=0),
        ]
    )
    return path

def create_scion_udp_packet(src_isd, src_as, dst_isd, dst_as, src_host, dst_host,
                             sport, dport, payload, underlay_dst=None, underlay_sport=32766):
    """Create SCION packet with IPv4 underlay"""
    
    if underlay_dst is None:
        underlay_dst = UNDERLAY_SERVER
    
    # Create path
    path = create_scion_path()
    
    # SCION packet (inner)
    scion = SCION(
        qos=0,
        fl=0x12345,
        dst_isd=dst_isd,
        dst_asn=str(dst_as),
        src_isd=src_isd,
        src_asn=str(src_as),
        dst_host=dst_host,
        src_host=src_host,
        path=path
    ) / UDP(
        sport=sport,
        dport=dport
    ) / Raw(load=payload)
    
    # Underlay (IPv4/UDP)
    pkt = IP(
        tos=0,
        ttl=64,
        id=0,
        flags="DF",
        frag=0,
        src="10.0.0.1",  # WG server IP
        dst=underlay_dst
    ) / UDP(
        sport=underlay_sport,
        dport=BR_PORT
    ) / scion
    
    return bytes(pkt)

def write_packets(packets, filepath):
    """Write packet to a binary file (direct bytes)"""
    with open(filepath, 'wb') as f:
        for pkt in packets:
            pkt_bytes = pkt if isinstance(pkt, bytes) else bytes(pkt)
            f.write(pkt_bytes)
    log_success(f"Wrote {len(packets)} packets to {filepath}")

def main():
    log_info("Generating SCION test packets...")
    
    # === Client -> Server direction (translated packet) ===
    # From AS64514 (client) to AS64513 (server)
    # Underlay goes to AS64513 BR (127.0.0.25:31006)
    
    pkt_client_to_server = create_scion_udp_packet(
        src_isd=1,
        src_as=64514,  # Client AS
        dst_isd=1,
        dst_as=64513,  # Server AS
        src_host=SCION_CLIENT_ADDR,
        dst_host=SCION_SERVER_ADDR,
        sport=12345,
        dport=30042,
        payload=PAYLOAD,
        underlay_dst=UNDERLAY_SERVER,
        underlay_sport=32766
    )
    
    write_packets(
        [pkt_client_to_server],
        f"{OUTPUT_DIR}/scion_client_to_server.bin"
    )
    
    # === Server -> Client direction (return traffic) ===
    # From AS64513 (server) to AS64514 (client)
    # Underlay goes to AS64514 BR (127.0.0.33:31010)
    
    pkt_server_to_client = create_scion_udp_packet(
        src_isd=1,
        src_as=64513,  # Server AS
        dst_isd=1,
        dst_as=64514,  # Client AS
        src_host=SCION_SERVER_ADDR,
        dst_host=SCION_CLIENT_ADDR,
        sport=30042,
        dport=12345,
        payload=PAYLOAD,
        underlay_dst=UNDERLAY_CLIENT,
        underlay_sport=32767
    )
    
    write_packets(
        [pkt_server_to_client],
        f"{OUTPUT_DIR}/scion_server_to_client.bin"
    )
    
    log_success("SCION packet generation complete!")
    log_info(f"Packets saved to {OUTPUT_DIR}/")
    
    # Print packet details
    print("\n" + "="*60)
    print("  Generated Packets")
    print("="*60)
    
    for fname in ["scion_client_to_server.bin", "scion_server_to_client.bin"]:
        fpath = f"{OUTPUT_DIR}/{fname}"
        with open(fpath, 'rb') as f:
            pkt_data = f.read()
            
            print(f"\n{fname}:")
            print(f"  Size: {len(pkt_data)} bytes")
            print(f"  Hex:  {pkt_data[:64].hex()}...")
            
            from scapy.all import Packet
            pkt = Packet(pkt_data)
            if IP in pkt:
                print(f"  Underlay: {pkt[IP].src} -> {pkt[IP].dst}")
            if UDP in pkt:
                print(f"  Underlay UDP: {pkt[UDP].sport} -> {pkt[UDP].dport}")
            if SCION in pkt:
                print(f"  SCION: {pkt[SCION].src_isd}-{pkt[SCION].src_asn} -> {pkt[SCION].dst_isd}-{pkt[SCION].dst_asn}")
                print(f"  SCION Host: {pkt[SCION].src_host} -> {pkt[SCION].dst_host}")

if __name__ == "__main__":
    main()
