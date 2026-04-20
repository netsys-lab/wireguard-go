#!/usr/bin/env python3
import os
import pickle
import sys
from pathlib import Path

import scapy.all
from scapy.layers.inet import IP, UDP


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))
from scapy_scion.layers.scion import SCION, UDP as SCIONUDP
from scapy_scion.layers.scmp import SCMP, ScmpEchoRequest, ScmpEchoReply


def sniff_and_save(count=1, filename="scion_pkts.pkl", filter=None, iface="lo"):
    """Sniff SCION packets and save to file."""
    print(f"Sniffing {count} packets on {iface}...")
    if filter:
        print(f"BPF filter: {filter}")
    pkts = scapy.all.sniff(count=count, iface=iface, filter=filter)
    with open(filename, "wb") as f:
        pickle.dump(pkts, f)
    print(f"Saved {len(pkts)} packets to {filename}")
    for i, p in enumerate(pkts):
        print(f"  [{i}] {p.summary()}")
    return pkts


def sniff_at_hop(src_port=None, dst_port=None, host=None, filename="scion_pkts.pkl"):
    """Sniff at a specific hop by source port, destination port, or host IP."""
    filters = []
    if src_port:
        filters.append(f"udp src port {src_port}")
    if dst_port:
        filters.append(f"udp dst port {dst_port}")
    if host:
        filters.append(f"host {host}")
    bpf = " and ".join(filters) if filters else None
    return sniff_and_save(count=1, filename=filename, filter=bpf)


def load_and_show(filename="scion_pkts.pkl"):
    """Load packets from file and show them."""
    with open(filename, "rb") as f:
        pkts = pickle.load(f)
    print(f"Loaded {len(pkts)} packets from {filename}")
    for i, p in enumerate(pkts):
        print(f"\n[{i}] {p.summary()}")
        p.show()
    return pkts


def replay_packet(filename="scion_pkts.pkl", index=0):
    """Load and send a packet."""
    with open(filename, "rb") as f:
        pkts = pickle.load(f)
    p = pkts[index]
    print(f"Replaying packet [{index}]:")
    p.show()
    ans = scapy.all.sr1(p, timeout=1)
    if ans:
        print("Response:")
        ans.show()
    return ans


def sniff_scion_pkts(ports=None, hosts=None, count=1, filename="scion_pkts.pkl", iface="lo"):
    """Sniff SCION packets by specific ports or hosts."""
    if hosts:
        h_filter = " or ".join([f"host {h}" for h in hosts])
    else:
        h_filter = None
    if ports:
        p_filter = " or ".join([f"udp port {p}" for p in ports])
    else:
        p_filter = None
    
    filters = []
    if h_filter:
        filters.append(h_filter)
    if p_filter:
        filters.append(p_filter)
    
    bpf = " and ".join(filters) if filters else "udp"
    print(f"BPF filter: {bpf}")
    return sniff_and_save(count, filename, bpf, iface)

    """
    elif args.hop:
        sniff_at_hop(args.src_port, args.dst_port, args.host, args.file)
    elif args.load:
        load_and_show(args.file)
    elif args.replay:
        replay_packet(args.file, args.index)
    else:
        print("Usage:")
        print("  # Sniff all SCION packets")
        print("  sudo ./sniff_scion.py --sniff -c 1 -f ping.pkl")
        print()
        print("  # Sniff at a specific hop (by port or IP)")
        print("  sudo ./sniff_scion.py --hop --src-port 50000 -f src.pkl")
        print("  sudo ./sniff_scion.py --hop --dst-port 50000 -f dst.pkl")
        print("  sudo ./sniff_scion.py --hop --host 127.0.0.7 -f hop.pkl")
        print()
        print("  # Load and show")
        print("  sudo ./sniff_scion.py --load -f ping.pkl")
        print()
        print("  # Replay")
        print("  sudo ./sniff_scion.py --replay -f ping.pkl")
        """