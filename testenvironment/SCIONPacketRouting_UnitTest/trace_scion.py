#!/usr/bin/env python3
"""
Trace SCION packets as they traverse border routers and save packets at source/destination.

Usage:
    # Trace from source AS to destination AS
    sudo ./trace_scion.py -s /home/paul/Scintra/scion --src-as 64513 --dst-as 64514

    # With custom output prefix
    sudo ./trace_scion.py -s /home/paul/Scintra/scion --src-as 64513 --dst-as 64514 -o my_trace
"""

import argparse
import json
import os
import pickle
import re
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

import scapy.fields
import scapy.layers.inet
from scapy.packet import Packet, bind_layers
from scapy.sendrecv import AsyncSniffer

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
from scapy_scion.layers.scion import SCION, UDP as SCIONUDP
from scapy_scion.layers.scmp import SCMP, ScmpEchoRequest, ScmpEchoReply
from scapy_scion.utils import capture_path, compare_layers


class SCIONPingSniffer:
    """Sniffer that captures SCION ping packets at each hop."""
    
    def __init__(self, brs: Dict[str, Any], src_iface: str, dst_iface: str, output_prefix: str = "trace",
                 numerical: bool = False, file_format: str = "bin", **kwargs):
        self.src_iface = src_iface  # e.g., "127.0.0.7:50000"
        self.dst_iface = dst_iface  # e.g., "127.0.0.11:50000"
        self.output_prefix = output_prefix
        self.num_addr = numerical
        self.packets: List[Packet] = []
        self.src_packets: List[Packet] = []
        self.dst_packets: List[Packet] = []
        self.format = file_format
        
        # Create BPF filter for source and destination interfaces
        src_ip, src_port = src_iface.split(":")
        dst_ip, dst_port = dst_iface.split(":")
        bpf = f"udp port {src_port} or udp port {dst_port}"
        
        self.sniffer = AsyncSniffer(
            iface="lo",
            store=False,
            filter=bpf,
            lfilter=self._filter,
            prn=self._prn,
            **kwargs
        )
        
        # Build address table for pretty printing
        self.addr_table = {}
        for br_name, br in brs.items():
            ip, port = br["internal_addr"].split(":")
            self.addr_table[(ip, int(port))] = f"{br_name}#i"
            for iface_name, iface in br["interfaces"].items():
                ip, port = iface["underlay"]["local"].split(":")
                self.addr_table[(ip, int(port))] = f"{br_name}#{iface_name}"
    
    def _filter(self, pkt: Packet) -> bool:
        """Filter for SCION packets with SCMP payload (ping)."""
        if not pkt.haslayer(SCION):
            return False
        return pkt[SCION].haslayer(SCMP)
    
    def _prn(self, pkt: Packet):
        ip = pkt[scapy.layers.inet.IP]
        udp = pkt.getlayer(SCIONUDP, 1)
        
        src_match = (ip.src, udp.sport)
        dst_match = (ip.dst, udp.dport)
        
        # Check if this is source or destination interface
        src_ip, src_port = self.src_iface.split(":")
        dst_ip, dst_port = self.dst_iface.split(":")
        
        is_at_src = (ip.dst == src_ip and udp.dport == int(src_port))
        is_at_dst = (ip.dst == dst_ip and udp.dport == int(dst_port))
        
        self.packets.append(pkt)
        
        if is_at_src:
            self.src_packets.append(pkt)
            print(f"[SRC] {ip.src}:{udp.sport} > {ip.dst}:{udp.dport} | SCION ping at source")
        elif is_at_dst:
            self.dst_packets.append(pkt)
            print(f"[DST] {ip.src}:{udp.sport} > {ip.dst}:{udp.dport} | SCION ping at destination")
        else:
            src = self.addr_table.get(src_match, f"{ip.src}:{udp.sport}")
            dst = self.addr_table.get(dst_match, f"{ip.dst}:{udp.dport}")
            print(f"[HOP] {src} > {dst} | SCION packet in transit")
        
        # Save packets after each capture
        self._save_packets()
    
    def _save_packets(self):
        """Save all captured packets to files."""
        ext = f".{self.format}"
        
        # Save all packets
        self._save_single(self.packets, f"{self.output_prefix}_all{ext}")
        
        # Save source packets
        if self.src_packets:
            self._save_single(self.src_packets, f"{self.output_prefix}_src{ext}")
        
        # Save destination packets
        if self.dst_packets:
            self._save_single(self.dst_packets, f"{self.output_prefix}_dst{ext}")
        
        ext_dot = f".{self.format}"
        print(f"  Saved: {self.output_prefix}_all{ext_dot} ({len(self.packets)}), "
              f"{self.output_prefix}_src{ext_dot} ({len(self.src_packets)}), "
              f"{self.output_prefix}_dst{ext_dot} ({len(self.dst_packets)})")
    
    def _save_single(self, packets, filename):
        """Save packets in the specified format."""
        if self.format == "pkl":
            with open(filename, "wb") as f:
                pickle.dump(packets, f)
        elif self.format == "bin":
            with open(filename, "wb") as f:
                for p in packets:
                    f.write(bytes(p))
        elif self.format == "pcap":
            from scapy.utils import PcapWriter
            with PcapWriter(filename, append=False, sync=True) as wrp:
                for p in packets:
                    wrp.write(p)
    
    def start(self):
        self.sniffer.start()
    
    def stop(self):
        self.sniffer.stop()
        self._save_packets()


def get_topology_info(scion_path: Path, src_as: str, dst_as: str) -> Dict[str, Any]:
    """Get source and destination interface addresses from topology."""
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
    
    # Get source interface (first interface of source AS)
    with open(scion_path / "gen" / src_as_formatted / "topology.json") as f:
        src_topo = json.load(f)
    
    # Get destination interface  
    with open(scion_path / "gen" / dst_as_formatted / "topology.json") as f:
        dst_topo = json.load(f)
    
    # Find interfaces - use interface 2 (last one, typically for traffic)
    src_br = list(src_topo["border_routers"].values())[0]
    dst_br = list(dst_topo["border_routers"].values())[0]
    
    # Get first interface
    src_iface = list(src_br["interfaces"].values())[0]["underlay"]["local"]
    dst_iface = list(dst_br["interfaces"].values())[0]["underlay"]["local"]
    
    # Get sciond addresses
    with open(scion_path / "gen" / "sciond_addresses.json") as f:
        scionds = json.load(f)
    
    return {
        "brs": brs,
        "src_iface": src_iface,  # e.g., "127.0.0.5:50000"
        "dst_iface": dst_iface,  # e.g., "127.0.0.9:50000"
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
        description="Trace SCION ping packets and save at source/destination"
    )
    parser.add_argument("-s", "--scion", type=Path, required=True,
        help="Path to SCION root (e.g., /home/paul/Scintra/scion)")
    parser.add_argument("--src-as", required=True, help="Source AS number (e.g., 64513)")
    parser.add_argument("--dst-as", required=True, help="Destination AS number (e.g., 64514)")
    parser.add_argument("-o", "--output", default="trace", help="Output prefix for files")
    parser.add_argument("-f", "--format", default="bin", choices=["bin", "pkl", "pcap"], 
                      help="Output format (default: bin)")
    parser.add_argument("-n", "--numerical", action="store_true", help="Show numerical addresses")
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of pings")
    args = parser.parse_args()
    
    print(f"=== SCION Packet Tracer ===")
    print(f"Source AS: {args.src_as}")
    print(f"Destination AS: {args.dst_as}")
    print(f"Output prefix: {args.output}")
    
    # Get topology info
    topo_info = get_topology_info(args.scion, args.src_as, args.dst_as)
    brs = topo_info["brs"]
    src_iface = topo_info["src_iface"]
    dst_iface = topo_info["dst_iface"]
    scionds = topo_info["scionds"]
    
    # Get source BR internal address
    src_as_formatted = f"AS{args.src_as}"
    with open(args.scion / "gen" / src_as_formatted / "topology.json") as f:
        src_topo = json.load(f)
    src_br = list(src_topo["border_routers"].values())[0]["internal_addr"]
    
    print(f"Source interface: {src_iface}")
    print(f"Destination interface: {dst_iface}")
    print(f"Source BR: {src_br}")
    
    # Bind SCION layers
    bind_scion_layers(brs)
    
    # Get sciond for source AS
    src_as_full = f"1-{args.src_as}"
    sciond = scionds[src_as_full] + ":30255"
    print(f"SCIOND: {sciond}")
    
    # Prepare destination
    dst = f"1-{args.dst_as},127.0.0.1"
    
    # Start sniffer
    print(f"\n### Starting sniffer...")
    started_event = threading.Event()
    sniffer = SCIONPingSniffer(
        brs, src_iface, dst_iface, args.output, args.numerical, args.format,
        started_callback=lambda: started_event.set()
    )
    sniffer.start()
    started_event.wait()
    
    # Send ping
    print(f"\n### Sending ping...")
    path = capture_path(str(args.scion / "bin/scion"), src_br, sciond, dst)
    
    # Wait for packets
    time.sleep(0.5)
    sniffer.stop()
    
    print(f"\n=== Results ===")
    print(f"Total packets captured: {len(sniffer.packets)}")
    print(f"Source packets: {len(sniffer.src_packets)}")
    print(f"Destination packets: {len(sniffer.dst_packets)}")
    
    if sniffer.src_packets:
        print(f"\n=== Source Packet ===")
        sniffer.src_packets[0].show()
    
    if sniffer.dst_packets:
        print(f"\n=== Destination Packet ===")
        sniffer.dst_packets[0].show()


if __name__ == "__main__":
    main()