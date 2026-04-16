#!/usr/bin/env python3
"""
Generate test packets for the integration test environment.
Creates IP (IPv6/UDP) packets that can be translated to SCION packets.

Usage:
    sudo python3 create_ip_packets.py

The packets are saved to testenvironment/packets/ip/
"""

import sys
import os
import struct
import socket

# Add scapy-scion path
sys.path.insert(0, '/home/paul/Scintra/scapy-scion-int')

from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from scapy.all import Raw

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
CLIENT_IP_V6 = "fd00::2"           # Client WG interface
SERVER_IP_V6 = "fd00::1"           # Server WG interface  
SCION_MAPPED_CLIENT = "fc00:10fc:200::2"  # Client SCION-mapped address (AS64514)
SCION_MAPPED_SERVER = "fc00:10fc:100::1"  # Server SCION-mapped address (AS64513)

# Test payload
PAYLOAD = b"TEST123"

# Output directory
OUTPUT_DIR = "/home/paul/Scintra/wireguard-go/testenvironment/packets/ip"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def create_ip_udp_packet(src_ip, dst_ip, sport, dport, payload):
    """Create IPv6/UDP packet"""
    pkt = IPv6(
        tc=0,
        fl=0x12345,
        hlim=64,
        src=src_ip,
        dst=dst_ip
    ) / UDP(
        sport=sport,
        dport=dport
    ) / Raw(load=payload)
    return bytes(pkt)

def write_packets(packets, filepath):
    """Write packet to a binary file (direct bytes)"""
    with open(filepath, 'wb') as f:
        for pkt in packets:
            pkt_bytes = pkt if isinstance(pkt, bytes) else bytes(pkt)
            f.write(pkt_bytes)
    log_success(f"Wrote {len(packets)} packets to {filepath}")

def main():
    log_info("Generating IP test packets...")
    
    # === Client -> Server direction ===
    # Packet from client to server via SCION-mapped addresses
    # This packet goes: Client TUN -> WG Client -> Translation -> WG Server -> TUN -> BR
    
    # Packet 1: UDP from Client to Server (SCION-mapped)
    # src: fd00::2 (client WG), dst: fc00:10fc:100::1 (server SCION-mapped)
    pkt_client_to_server = create_ip_udp_packet(
        src_ip=CLIENT_IP_V6,
        dst_ip=SCION_MAPPED_SERVER,  # Server AS64513
        sport=12345,
        dport=30042,  # Echo server port
        payload=PAYLOAD
    )
    
    write_packets(
        [pkt_client_to_server],
        f"{OUTPUT_DIR}/ip_client_to_server.bin"
    )
    
    # === Server -> Client direction (return traffic) ===
    # Packet from server back to client
    # src: fc00:10fc:100::1 (server SCION-mapped), dst: fc00:10fc:200::2 (client SCION-mapped)
    pkt_server_to_client = create_ip_udp_packet(
        src_ip=SCION_MAPPED_SERVER,
        dst_ip=SCION_MAPPED_CLIENT,
        sport=30042,
        dport=12345,
        payload=PAYLOAD
    )
    
    write_packets(
        [pkt_server_to_client],
        f"{OUTPUT_DIR}/ip_server_to_client.bin"
    )
    
    log_success("IP packet generation complete!")
    log_info(f"Packets saved to {OUTPUT_DIR}/")
    
    # Print packet details
    print("\n" + "="*60)
    print("  Generated Packets")
    print("="*60)
    
    for fname in ["ip_client_to_server.bin", "ip_server_to_client.bin"]:
        fpath = f"{OUTPUT_DIR}/{fname}"
        with open(fpath, 'rb') as f:
            pkt_data = f.read()
            
            print(f"\n{fname}:")
            print(f"  Size: {len(pkt_data)} bytes")
            print(f"  Hex:  {pkt_data[:32].hex()}...")
            
            from scapy.all import Packet
            pkt = Packet(pkt_data)
            if IPv6 in pkt:
                print(f"  IPv6: {pkt[IPv6].src} -> {pkt[IPv6].dst}")
            if UDP in pkt:
                print(f"  UDP:  {pkt[UDP].sport} -> {pkt[UDP].dport}")

if __name__ == "__main__":
    main()
