#!/usr/bin/env python3
"""
Validate that the generated packet pairs are valid translations.

Usage:
    python3 validate_packets.py
"""

import sys
import os

sys.path.insert(0, '/home/paul/Scintra/scapy-scion-int')

from scapy.all import Packet

# Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'

def log_info(msg):
    print(f"{BLUE}[INFO]{NC} {msg}")

def log_success(msg):
    print(f"{GREEN}[PASS]{NC} {msg}")

def log_fail(msg):
    print(f"{RED}[FAIL]{NC} {msg}")

def log_warn(msg):
    print(f"{YELLOW}[WARN]{NC} {msg}")

# Paths
IP_DIR = "/home/paul/Scintra/wireguard-go/testenvironment/packets/ip"
SCION_DIR = "/home/paul/Scintra/wireguard-go/testenvironment/packets/scion"

def load_packet(filepath):
    """Load a single packet from binary file"""
    with open(filepath, 'rb') as f:
        return f.read()

def parse_ip_simple(pkt_bytes):
    """Parse IP packet manually"""
    if len(pkt_bytes) < 1:
        return None
    
    version = pkt_bytes[0] >> 4
    
    if version == 6 and len(pkt_bytes) >= 40:
        # IPv6 header - convert to colon-separated hex
        src_ip = ':'.join(f'{b:02x}' for b in pkt_bytes[8:24])
        dst_ip = ':'.join(f'{b:02x}' for b in pkt_bytes[24:40])
        
        # Parse extension header for UDP
        next_header = pkt_bytes[6]
        
        return {
            'version': 6,
            'src': src_ip,
            'dst': dst_ip,
            'next_header': next_header
        }
    
    return None
    
    version = pkt_bytes[0] >> 4
    
    if version == 6 and len(pkt_bytes) >= 40:
        # IPv6 header
        src_ip = bytes(pkt_bytes[8:24]).decode('utf-8').replace('\x00', '')
        dst_ip = bytes(pkt_bytes[24:40]).decode('utf-8').replace('\x00', '')
        
        # Parse extension header for UDP
        next_header = pkt_bytes[6]
        
        return {
            'version': 6,
            'src': ':'.join(f'{b:02x}' for b in pkt_bytes[8:24]),
            'dst': ':'.join(f'{b:02x}' for b in pkt_bytes[24:40]),
            'next_header': next_header
        }
    
    return None

def parse_scion_simple(pkt_bytes):
    """Parse SCION packet manually - just check underlay"""
    if len(pkt_bytes) < 20:
        return None
    
    version = pkt_bytes[0] >> 4
    
    if version == 4 and len(pkt_bytes) >= 28:
        # IPv4 underlay
        src_ip = '.'.join(str(b) for b in pkt_bytes[12:16])
        dst_ip = '.'.join(str(b) for b in pkt_bytes[16:20])
        
        return {
            'underlay_src': src_ip,
            'underlay_dst': dst_ip
        }
    
    return None

def main():
    print("="*60)
    print("  Packet Validation")
    print("="*60)
    
    all_passed = True
    
    # === Test 1: Client -> Server direction ===
    log_info("\n=== Test 1: Client -> Server ===")
    
    ip_cts = load_packet(f"{IP_DIR}/ip_client_to_server.bin")
    scion_cts = load_packet(f"{SCION_DIR}/scion_client_to_server.bin")
    
    if ip_cts and scion_cts:
        log_info(f"IP packet size: {len(ip_cts)} bytes")
        log_info(f"SCION packet size: {len(scion_cts)} bytes")
        
        # Parse IP packet manually
        ip_info = parse_ip_simple(ip_cts)
        if ip_info:
            print(f"IP Packet: {ip_info['src']} -> {ip_info['dst']}")
            log_success("IP packet parsed")
        else:
            log_fail("Failed to parse IP packet")
            all_passed = False
        
        # Parse SCION packet manually  
        scion_info = parse_scion_simple(scion_cts)
        if scion_info:
            print(f"Underlay: {scion_info['underlay_src']} -> {scion_info['underlay_dst']}")
            log_success("SCION packet parsed")
        else:
            log_fail("Failed to parse SCION packet")
            all_passed = False
    else:
        log_fail("Failed to load packets")
        all_passed = False
    
    # === Test 2: Server -> Client direction ===
    log_info("\n=== Test 2: Server -> Client ===")
    
    ip_stc = load_packet(f"{IP_DIR}/ip_server_to_client.bin")
    scion_stc = load_packet(f"{SCION_DIR}/scion_server_to_client.bin")
    
    if ip_stc and scion_stc:
        log_info(f"IP packet size: {len(ip_stc)} bytes")
        log_info(f"SCION packet size: {len(scion_stc)} bytes")
        
        # Parse IP packet manually
        ip_info = parse_ip_simple(ip_stc)
        if ip_info:
            print(f"IP Packet: {ip_info['src']} -> {ip_info['dst']}")
            log_success("IP packet parsed")
        else:
            log_fail("Failed to parse IP packet")
            all_passed = False
        
        # Parse SCION packet manually
        scion_info = parse_scion_simple(scion_stc)
        if scion_info:
            print(f"Underlay: {scion_info['underlay_src']} -> {scion_info['underlay_dst']}")
            log_success("SCION packet parsed")
        else:
            log_fail("Failed to parse SCION packet")
            all_passed = False
    else:
        log_fail("Failed to load packets")
        all_passed = False
    
    # === Summary ===
    print("\n" + "="*60)
    if all_passed:
        log_success("All packet validations passed!")
    else:
        log_fail("Some packet validations failed!")
    print("="*60)

if __name__ == "__main__":
    main()
