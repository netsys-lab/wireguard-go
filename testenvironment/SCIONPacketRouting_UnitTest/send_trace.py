#!/usr/bin/env python3
"""
Send a custom SCION packet and trace it as it traverses border routers.

Usage:
    # Send a custom .bin packet and trace it
    sudo ./send_trace.py -s /home/paul/Scintra/scion --src-as 64513 --dst-as 64514 -p custom.bin -o trace

    # Send a .pkl packet
    sudo ./send_trace.py -s /home/paul/Scintra/scion --src-as 64513 --dst-as 64514 -p custom.pkl -f pkl

    # Send and show hop details
    sudo ./send_trace.py -s /home/paul/Scintra/scion --src-as 64513 --dst-as 64514 -p custom.bin -v
"""

import argparse
import json
import os
import pickle
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping

import scapy.layers.inet
import scapy.fields
from scapy.packet import Packet, bind_layers
from scapy.sendrecv import AsyncSniffer, send

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
from scapy_scion.layers.scion import SCION, UDP as SCIONUDP
from scapy_scion.layers.scmp import SCMP, ScmpEchoRequest, ScmpEchoReply
from scapy_scion.utils import compare_layers


class PacketSniffer:
    """Sniffer that captures packets at each hop."""
    
    def __init__(self, brs: Dict[str, Any], output_prefix: str = "trace",
                 numerical: bool = False, verbose: bool = False, **kwargs):
        self.output_prefix = output_prefix
        self.num_addr = numerical
        self.verbose = verbose
        self.packets: List[Packet] = []
        self.hop_packets: List[Packet] = []
        
        # Build address table for pretty printing
        self.addr_table = {}
        for br_name, br in brs.items():
            ip, port = br["internal_addr"].split(":")
            self.addr_table[(ip, int(port))] = f"{br_name}#i"
            for iface_name, iface in br["interfaces"].items():
                ip, port = iface["underlay"]["local"].split(":")
                self.addr_table[(ip, int(port))] = f"{br_name}#{iface_name}"
        
        # Sniffer with no filter - capture all and filter in _prn
        self.sniffer = AsyncSniffer(
            iface="lo",
            store=False,
            lfilter=self._filter,
            prn=self._prn,
            **kwargs
        )
    
    def _filter(self, pkt: Packet) -> bool:
        """Filter for SCION packets."""
        return pkt.haslayer(SCION)
    
    def _prn(self, pkt: Packet):
        if not pkt.haslayer(SCION):
            return
        
        ip = pkt[scapy.layers.inet.IP]
        udp = pkt.getlayer(SCIONUDP, 1)
        
        src_match = (ip.src, udp.sport)
        dst_match = (ip.dst, udp.dport)
        
        src = self.addr_table.get(src_match, f"{ip.src}:{udp.sport}")
        dst = self.addr_table.get(dst_match, f"{ip.dst}:{udp.dport}")
        
        self.packets.append(pkt)
        self.hop_packets.append(pkt)
        
        print(f"[HOP] {src} > {dst} | SCION packet")
        
        if self.verbose and len(self.hop_packets) > 1:
            last = self.hop_packets[-2]
            curr = self.hop_packets[-1]
            if last[SCION].haslayer(curr[SCION].payload.__class__):
                for diff in compare_layers(last[SCION], curr[SCION]):
                    print(f"      {diff[0]}: {diff[1]} -> {diff[2]}")
    
    def start(self):
        self.sniffer.start()
    
    def stop(self):
        self.sniffer.stop()


def load_packet(path: str, file_format: str = "bin") -> Packet:
    """Load a packet from file."""
    if file_format == "bin":
        # Raw bytes - need scapy to parse
        with open(path, "rb") as f:
            data = f.read()
        # Try to parse as SCION packet
        from scapy.layers.l2 import Ether
        return Ether(data)
    elif file_format == "pkl":
        with open(path, "rb") as f:
            packets = pickle.load(f)
        if isinstance(packets, list):
            return packets[0]
        return packets
    elif file_format == "pcap":
        from scapy.utils import PcapReader
        with PcapReader(path) as reader:
            return next(reader)
    else:
        raise ValueError(f"Unknown format: {file_format}")


def send_packet(pkt: Packet, dst: str, dst_port: int):
    """Send packet to destination."""
    ip = pkt[scapy.layers.inet.IP]
    # Update destination
    ip.dst = dst
    # Update UDP port
    udp = pkt.getlayer(SCIONUDP, 1)
    if udp:
        udp.dport = dst_port
    print(f"Sending packet to {dst}:{dst_port}")
    send(pkt)


def get_topology_info(scion_path: Path, src_as: str, dst_as: str) -> Dict[str, Any]:
    """Get source and destination info from topology."""
    src_as_formatted = f"AS{src_as}"
    dst_as_formatted = f"AS{dst_as}"
    
    brs = {}
    topo_paths = {
        src_as: scion_path / "gen" / src_as_formatted / "topology.json",
        dst_as: scion_path / "gen" / dst_as_formatted / "topology.json",
    }
    
    for asn, topo_path in topo_paths.items():
        with open(topo_path) as f:
            topo = json.load(f)
            brs.update(topo["border_routers"])
    
    # Get source BR internal address
    with open(scion_path / "gen" / src_as_formatted / "topology.json") as f:
        src_topo = json.load(f)
    
    src_br = list(src_topo["border_routers"].values())[0]["internal_addr"]
    src_ip, src_port = src_br.split(":")
    
    # Get destination info
    with open(scion_path / "gen" / dst_as_formatted / "topology.json") as f:
        dst_topo = json.load(f)
    
    # Get first interface for destination
    dst_br = list(dst_topo["border_routers"].values())[0]
    dst_iface = list(dst_br["interfaces"].values())[0]["underlay"]["local"]
    dst_ip, dst_port = dst_iface.split(":")
    dst_port = int(dst_port)
    
    # Get sciond addresses
    with open(scion_path / "gen" / "sciond_addresses.json") as f:
        scionds = json.load(f)
    
    return {
        "brs": brs,
        "src_br": src_br,
        "src_ip": src_ip,
        "src_port": int(src_port),
        "dst_iface": dst_iface,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "scionds": scionds,
    }


def bind_scion_layers(brs: Mapping[str, Any]):
    """Bind SCION layer to UDP packets at BR interfaces."""
    for br in brs.values():
        _, port = br["internal_addr"].split(":")
        bind_layers(SCIONUDP, SCION, sport=int(port))
        bind_layers(SCIONUDP, SCION, dport=int(port))
        for iface in br["interfaces"].values():
            _, port = iface["underlay"]["local"].split(":")
            bind_layers(SCIONUDP, SCION, sport=int(port))
            bind_layers(SCIONUDP, SCION, dport=int(port))


def main():
    parser = argparse.ArgumentParser(
        description="Send a custom SCION packet and trace it"
    )
    parser.add_argument("-s", "--scion", type=Path, required=True,
        help="Path to SCION root (e.g., /home/paul/Scintra/scion)")
    parser.add_argument("--src-as", required=True, help="Source AS number (e.g., 64513)")
    parser.add_argument("--dst-as", required=True, help="Destination AS number (e.g., 64514)")
    parser.add_argument("-p", "--packet", required=True, help="Path to packet file (.bin, .pkl, .pcap)")
    parser.add_argument("-f", "--format", default="bin", choices=["bin", "pkl", "pcap"], 
                      help="Packet file format (default: bin)")
    parser.add_argument("-o", "--output", default="trace", help="Output prefix")
    parser.add_argument("-n", "--numerical", action="store_true", help="Show numerical addresses")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed changes at each hop")
    parser.add_argument("-t", "--timeout", type=int, default=2, help="Timeout in seconds")
    args = parser.parse_args()
    
    print(f"=== Custom SCION Packet Sender ===")
    print(f"Source AS: {args.src_as}")
    print(f"Destination AS: {args.dst_as}")
    print(f"Packet file: {args.packet}")
    print(f"Format: {args.format}")
    
    # Get topology info
    topo_info = get_topology_info(args.scion, args.src_as, args.dst_as)
    brs = topo_info["brs"]
    src_br = topo_info["src_br"]
    dst_ip = topo_info["dst_ip"]
    dst_port = topo_info["dst_port"]
    scionds = topo_info["scionds"]
    
    print(f"Source BR: {src_br}")
    print(f"Destination: {dst_ip}:{dst_port}")
    
    # Bind SCION layers
    bind_scion_layers(brs)
    
    # Load packet
    print(f"\n### Loading packet from {args.packet}...")
    pkt = load_packet(args.packet, args.format)
    print(f"Loaded packet: {pkt.summary()}")
    
    if args.verbose:
        print("\n=== Original Packet ===")
        pkt.show()
    
    # Start sniffer
    print(f"\n### Starting sniffer...")
    started_event = threading.Event()
    sniffer = PacketSniffer(brs, args.output, args.numerical, args.verbose,
                           started_callback=lambda: started_event.set())
    sniffer.start()
    started_event.wait()
    time.sleep(0.1)  # Let sniffer settle
    
    # Send packet
    print(f"\n### Sending packet...")
    send_packet(pkt, dst_ip, dst_port)
    
    # Wait for packets
    time.sleep(args.timeout)
    sniffer.stop()
    
    print(f"\n=== Results ===")
    print(f"Total packets captured: {len(sniffer.packets)}")
    print(f"Hops: {len(sniffer.hop_packets)}")
    
    # Save packets
    ext = f".{args.format}"
    with open(f"{args.output}_all{ext}", "wb") as f:
        if args.format == "bin":
            for p in sniffer.packets:
                f.write(bytes(p))
        elif args.format == "pkl":
            pickle.dump(sniffer.packets, f)
        elif args.format == "pcap":
            from scapy.utils import PcapWriter
            with PcapWriter(f"{args.output}_all{ext}", append=False, sync=True) as wrp:
                for p in sniffer.packets:
                    wrp.write(p)
    
    print(f"Saved: {args.output}_all{ext}")
    
    if sniffer.hop_packets:
        print(f"\n=== First Hop ===")
        sniffer.hop_packets[0].show()
        print(f"\n=== Last Hop ===")
        sniffer.hop_packets[-1].show()


if __name__ == "__main__":
    main()