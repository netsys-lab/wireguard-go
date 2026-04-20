"""
Send a custom SCION packet and trace it as it traverses border routers.

Examples:
    sudo ./send_trace.py \
        -s /home/paul/Scintra/scion \
        --src-as 64513 \
        --dst-as 64514 \
        -p custom.bin

    sudo ./send_trace.py \
        -s /home/paul/Scintra/scion \
        --src-as 64513 \
        --dst-as 64514 \
        -p custom.pkl \
        -f pkl

    sudo ./send_trace.py \
        -s /home/paul/Scintra/scion \
        --src-as 64513 \
        --dst-as 64514 \
        -p custom.pcap \
        -f pcap \
        -v
"""

import argparse
import json
import os
import pickle
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

import scapy.layers.inet
from scapy.layers.inet import IP
from scapy.packet import Packet, Raw, bind_layers
from scapy.sendrecv import AsyncSniffer, send
from scapy.utils import PcapReader, PcapWriter

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../")))

from scapy_scion.layers.scion import SCION, UDP as SCIONUDP
from scapy_scion.layers.scmp import SCMP
from scapy_scion.utils import compare_layers


def infer_format(path: str, explicit_format: Optional[str]) -> str:
    if explicit_format is not None:
        return explicit_format
    suffix = Path(path).suffix.lower()
    if suffix == ".pcap":
        return "pcap"
    if suffix == ".pkl":
        return "pkl"
    return "bin"


def packet_marker(pkt: Packet) -> Optional[bytes]:
    if pkt.haslayer(Raw):
        try:
            return bytes(pkt[Raw].load)
        except Exception:
            return None
    return None


def get_scmp_id(pkt: Packet) -> Optional[int]:
    if not pkt.haslayer(SCMP):
        return None
    msg = pkt[SCMP].message
    return getattr(msg, "id", None)


def safe_get_udp(pkt: Packet) -> Optional[Packet]:
    udp = pkt.getlayer(SCIONUDP, 1)
    if udp is None:
        udp = pkt.getlayer(scapy.layers.inet.UDP, 1)
    return udp


class PacketSniffer:
    """Sniffer that captures only packets matching the injected packet."""

    def __init__(
        self,
        brs: Dict[str, Any],
        target_pkt: Optional[Packet] = None,
        output_prefix: str = "trace",
        numerical: bool = False,
        verbose: bool = False,
        **kwargs,
    ):
        self.output_prefix = output_prefix
        self.num_addr = numerical
        self.verbose = verbose
        self.packets: List[Packet] = []
        self.hop_packets: List[Packet] = []
        self.target_pkt = target_pkt

        self.addr_table = {}
        for br_name, br in brs.items():
            ip, port = br["internal_addr"].split(":")
            self.addr_table[(ip, int(port))] = f"{br_name}#i"
            for iface_name, iface in br["interfaces"].items():
                ip, port = iface["underlay"]["local"].split(":")
                self.addr_table[(ip, int(port))] = f"{br_name}#{iface_name}"

        self.expected_marker = packet_marker(target_pkt) if target_pkt is not None else None
        self.expected_scmp_type = target_pkt[SCMP].type if target_pkt is not None and target_pkt.haslayer(SCMP) else None
        self.expected_scmp_id = get_scmp_id(target_pkt) if target_pkt is not None else None

        self.sniffer = AsyncSniffer(
            iface="lo",
            store=False,
            lfilter=self._filter,
            prn=self._prn,
            **kwargs,
        )

    def _matches_target(self, pkt: Packet) -> bool:
        if self.target_pkt is None:
            return pkt.haslayer(SCION)

        if not pkt.haslayer(SCION) or not self.target_pkt.haslayer(SCION):
            return False

        current = pkt[SCION]
        target = self.target_pkt[SCION]

        if current.nh != target.nh:
            return False
        if current.src_isd != target.src_isd or current.src_asn != target.src_asn:
            return False
        if current.dst_isd != target.dst_isd or current.dst_asn != target.dst_asn:
            return False
        if str(current.src_host) != str(target.src_host):
            return False
        if str(current.dst_host) != str(target.dst_host):
            return False

        if self.expected_scmp_type is not None:
            if not pkt.haslayer(SCMP):
                return False
            if pkt[SCMP].type != self.expected_scmp_type:
                return False

        if self.expected_scmp_id is not None:
            current_id = get_scmp_id(pkt)
            if current_id != self.expected_scmp_id:
                return False

        if self.expected_marker:
            try:
                raw_bytes = bytes(pkt)
            except Exception:
                return False
            if self.expected_marker not in raw_bytes:
                return False

        return True

    def _filter(self, pkt: Packet) -> bool:
        return self._matches_target(pkt)

    def _prn(self, pkt: Packet):
        if not pkt.haslayer(SCION):
            return

        ip = pkt.getlayer(IP)
        udp = safe_get_udp(pkt)
        if ip is None or udp is None:
            return

        src_match = (ip.src, udp.sport)
        dst_match = (ip.dst, udp.dport)

        src = self.addr_table.get(src_match, f"{ip.src}:{udp.sport}")
        dst = self.addr_table.get(dst_match, f"{ip.dst}:{udp.dport}")

        self.packets.append(pkt)
        self.hop_packets.append(pkt)

        extra = ""
        if pkt.haslayer(SCMP):
            extra = f" | SCMP type={pkt[SCMP].type}"
            scmp_id = get_scmp_id(pkt)
            if scmp_id is not None:
                extra += f" id={scmp_id}"

        print(f"[HOP] {src} > {dst} | SCION packet{extra}")

        if self.verbose and len(self.hop_packets) > 1:
            last = self.hop_packets[-2]
            curr = self.hop_packets[-1]
            try:
                for diff in compare_layers(last[SCION], curr[SCION]):
                    print(f"      {diff[0]}: {diff[1]} -> {diff[2]}")
            except Exception:
                pass

    def start(self):
        self.sniffer.start()

    def stop(self):
        self.sniffer.stop()


def load_packet(path: str, file_format: str = "bin") -> Packet:
    """Load a packet from file."""
    if file_format == "bin":
        with open(path, "rb") as f:
            data = f.read()
        return IP(data)

    if file_format == "pkl":
        with open(path, "rb") as f:
            packets = pickle.load(f)
        if isinstance(packets, list):
            return packets[0]
        return packets

    if file_format == "pcap":
        with PcapReader(path) as reader:
            return next(reader)

    raise ValueError(f"Unknown format: {file_format}")


def send_packet(pkt: Packet, dst: str, dst_port: int):
    """Send packet to destination underlay."""
    ip = pkt.getlayer(IP)
    if ip is None:
        raise ValueError("Packet does not contain an IP layer")

    udp = safe_get_udp(pkt)
    if udp is None:
        raise ValueError("Packet does not contain a UDP layer")

    ip.dst = dst
    udp.dport = dst_port

    if pkt.haslayer(IP):
        if hasattr(pkt[IP], "len"):
            del pkt[IP].len
        if hasattr(pkt[IP], "chksum"):
            del pkt[IP].chksum

    if udp is not None:
        if hasattr(udp, "len"):
            del udp.len
        if hasattr(udp, "chksum"):
            del udp.chksum

    print(f"Sending packet to {dst}:{dst_port}")
    send(pkt, verbose=True)


def get_topology_info(scion_path: Path, src_as: str, dst_as: str) -> Dict[str, Any]:
    """Get source and destination info from topology."""
    src_as_formatted = f"AS{src_as}"
    dst_as_formatted = f"AS{dst_as}"

    brs = {}
    topo_paths = {
        src_as: scion_path / "gen" / src_as_formatted / "topology.json",
        dst_as: scion_path / "gen" / dst_as_formatted / "topology.json",
    }

    for _, topo_path in topo_paths.items():
        with open(topo_path) as f:
            topo = json.load(f)
            brs.update(topo["border_routers"])

    with open(scion_path / "gen" / src_as_formatted / "topology.json") as f:
        src_topo = json.load(f)

    src_br = list(src_topo["border_routers"].values())[0]["internal_addr"]
    src_ip, src_port = src_br.split(":")

    with open(scion_path / "gen" / dst_as_formatted / "topology.json") as f:
        dst_topo = json.load(f)

    dst_br = list(dst_topo["border_routers"].values())[0]
    dst_iface = list(dst_br["interfaces"].values())[0]["underlay"]["local"]
    dst_ip, dst_port = dst_iface.split(":")
    dst_port = int(dst_port)

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


def print_packet_identity(pkt: Packet):
    print("\n=== Packet being sent ===")
    pkt.show()

    if pkt.haslayer(SCION):
        s = pkt[SCION]
        line = (
            f"SCION src={s.src_isd}-{s.src_asn},{s.src_host} "
            f"dst={s.dst_isd}-{s.dst_asn},{s.dst_host} nh={s.nh}"
        )
        if pkt.haslayer(SCMP):
            line += f" scmp_type={pkt[SCMP].type}"
            scmp_id = get_scmp_id(pkt)
            if scmp_id is not None:
                line += f" scmp_id={scmp_id}"
        print(line)

    marker = packet_marker(pkt)
    if marker is not None:
        print(f"Raw marker: {marker!r}")


def main():
    parser = argparse.ArgumentParser(
        description="Send a custom SCION packet and trace it"
    )
    parser.add_argument(
        "-s", "--scion", type=Path, required=True,
        help="Path to SCION root (e.g., /home/paul/Scintra/scion)"
    )
    parser.add_argument("--src-as", required=True, help="Source AS number (e.g., 64513)")
    parser.add_argument("--dst-as", required=True, help="Destination AS number (e.g., 64514)")
    parser.add_argument("-p", "--packet", required=True, help="Path to packet file (.bin, .pkl, .pcap)")
    parser.add_argument(
        "-f", "--format", choices=["bin", "pkl", "pcap"],
        help="Packet file format (default: infer from extension)"
    )
    parser.add_argument("-o", "--output", default="trace", help="Output prefix")
    parser.add_argument("-n", "--numerical", action="store_true", help="Show numerical addresses")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed changes at each hop")
    parser.add_argument("-t", "--timeout", type=int, default=2, help="Timeout in seconds")
    args = parser.parse_args()

    args.format = infer_format(args.packet, args.format)

    print("=== Custom SCION Packet Sender ===")
    print(f"Source AS: {args.src_as}")
    print(f"Destination AS: {args.dst_as}")
    print(f"Packet file: {args.packet}")
    print(f"Format: {args.format}")

    topo_info = get_topology_info(args.scion, args.src_as, args.dst_as)
    brs = topo_info["brs"]
    src_br = topo_info["src_br"]
    dst_ip = topo_info["dst_ip"]
    dst_port = topo_info["dst_port"]

    print(f"Source BR: {src_br}")
    print(f"Destination: {dst_ip}:{dst_port}")

    bind_scion_layers(brs)

    print(f"\n### Loading packet from {args.packet}...")
    pkt = load_packet(args.packet, args.format)
    print(f"Loaded packet: {pkt.summary()}")

    print_packet_identity(pkt)

    print("\n### Starting sniffer...")
    started_event = threading.Event()
    sniffer = PacketSniffer(
        brs,
        target_pkt=pkt.copy(),
        output_prefix=args.output,
        numerical=args.numerical,
        verbose=args.verbose,
        started_callback=lambda: started_event.set(),
    )
    sniffer.start()
    started_event.wait()
    time.sleep(0.1)

    print("\n### Sending packet...")
    send_packet(pkt, dst_ip, dst_port)

    time.sleep(args.timeout)
    sniffer.stop()

    print("\n=== Results ===")
    print(f"Total packets captured: {len(sniffer.packets)}")
    print(f"Hops: {len(sniffer.hop_packets)}")

    ext = f".{args.format}"
    out_path = f"{args.output}_all{ext}"

    if args.format == "bin":
        with open(out_path, "wb") as f:
            for p in sniffer.packets:
                f.write(bytes(p))
    elif args.format == "pkl":
        with open(out_path, "wb") as f:
            pickle.dump(sniffer.packets, f)
    elif args.format == "pcap":
        with PcapWriter(out_path, append=False, sync=True) as wrp:
            for p in sniffer.packets:
                wrp.write(p)

    print(f"Saved: {out_path}")

    if sniffer.hop_packets:
        print("\n=== First Hop ===")
        sniffer.hop_packets[0].show()
        print("\n=== Last Hop ===")
        sniffer.hop_packets[-1].show()
    else:
        print("\nNo matching packets captured.")
        print("Try increasing --timeout or make the packet marker/id more unique.")


if __name__ == "__main__":
    main()