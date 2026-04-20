#!/usr/bin/env python3
"""
SCION Packet Sender

Sendet ein pcap File an die SCION Topology.

Verwendung:
    python3 send_packets.py packet_peer_link_with_path.pcap
    python3 send_packets.py packet_core_route.pcap
    python3 send_packets.py <pcap_file>
"""

import sys
import os
import argparse

sys.path.insert(0, "/home/paul/Scintra/scapy-scion-int")

from scapy.all import send, rdpcap, IP
from scapy.layers.inet import UDP as ScapyUDP

# ==============================================================================
# KONFIGURATION
# ==============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ==============================================================================
# SENDEN
# ==============================================================================

def send_packet(pcap_file):
    """Sendet alle Packete aus dem pcap File."""
    
    full_path = pcap_file
    if not os.path.isabs(pcap_file):
        full_path = os.path.join(SCRIPT_DIR, pcap_file)
    
    if not os.path.exists(full_path):
        print(f"[ERROR] File not found: {full_path}")
        return 1
    
    print("=" * 70)
    print(f"SENDING: {os.path.basename(full_path)}")
    print("=" * 70)
    
    packets = rdpcap(full_path)
    
    print(f"[LOADED] {len(packets)} packet(s)")
    print()
    
    for i, packet in enumerate(packets):
        if IP in packet:
            print(f"[PACKET {i+1}]")
            print(f"  IP dst:   {packet[IP].dst}")
            if ScapyUDP in packet:
                print(f"  UDP dport: {packet[ScapyUDP].dport}")
            
            # Show SCION info if present
            if packet.haslayer(SCION := __import__('scapy_scion.layers.scion', fromlist=['SCION']).SCION):
                scion_layer = packet[SCION]
                print(f"  SCION:")
                print(f"    src: {scion_layer.src_isd}-{scion_layer.src_asn}")
                print(f"    dst: {scion_layer.dst_isd}-{scion_layer.dst_asn}")
                print(f"    ptype: {scion_layer.ptype}")
            
            print()
            
            # Send
            print(f"[SENDING packet {i+1}]...")
            send(packet)
            print(f"[OK] Packet {i+1} sent!")
            print()
    
    print("[DONE] All packets sent!")
    
    print("\n[CHECK]:")
    print("  Jaeger:    http://localhost:16686")
    print("  tcpdump:  sudo tcpdump -i lo port 50000 -v")
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="SCION Packet Sender",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
    python3 send_packets.py packet_peer_link_with_path.pcap
    python3 send_packets.py packet_core_route.pcap
    python3 send_packets.py /path/to/custom.pcap
        """
    )
    parser.add_argument("pcap", nargs="?", help="pcap file to send")
    parser.add_argument("--list", action="store_true", help="list available pcap files")
    
    args = parser.parse_args()
    
    if args.list:
        print("Verfügbare pcap Files:")
        for f in os.listdir(SCRIPT_DIR):
            if f.endswith(".pcap"):
                print(f"  {f}")
        return 0
    
    if not args.pcap:
        parser.print_help()
        print("\nVerfügbare pcap Files:")
        for f in os.listdir(SCRIPT_DIR):
            if f.endswith(".pcap"):
                print(f"  {f}")
        return 0
    
    print("""
╔═══════════════════════════════════════════════════════════════════════╗
║  SCION Packet Sender                                              ║
║  ───────────────────────────────────────────────────────────────    ║
║  Make sure SCION is running first:                                 ║
║    cd /home/paul/Scintra/scion                                    ║
║    ./scion.sh status                                             ║
╚═══════════════════════════════════════════════════════════════════════╝
""")
    
    return send_packet(args.pcap)


if __name__ == "__main__":
    sys.exit(main())