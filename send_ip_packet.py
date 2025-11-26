"""
Dieses Script erstellt IP-Pakete (IPv4 oder IPv6) und schickt sie an eine Zieladresse.

Die Zieladresse wird bei Ausführung als Argument übergeben.
Das Paket wird, wenn nicht anders spezifiziert, über das System-Routing / das angegebene Interface verschickt.
"""

import argparse
import ipaddress
from scapy.all import conf, send, IP, IPv6, UDP, Raw
import sys

def is_ipv6_address(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).version == 6
    except ValueError:
        raise ValueError(f"Ungültige IP-Adresse: {addr}")

def build_pkt(dst: str, port: int, src: str | None):
    # Bestimme Version anhand der Adresse
    dst_is_v6 = is_ipv6_address(dst)

    # Wenn src angegeben, prüfen, ob die Version übereinstimmt
    if src:
        try:
            src_is_v6 = ipaddress.ip_address(src).version == 6
        except ValueError:
            raise ValueError(f"Ungültige Quelladresse: {src}")
        if src_is_v6 != dst_is_v6:
            raise ValueError("Quell- und Zieladresse müssen dieselbe IP-Version haben (beide IPv4 oder beide IPv6).")
    else:
        src_is_v6 = None

    # Erzeuge IP-Layer passend zur Version
    if dst_is_v6:
        ip_layer = IPv6(dst=dst)
        if src:
            ip_layer.src = src
    else:
        ip_layer = IP(dst=dst)
        if src:
            ip_layer.src = src

    # L4: UDP (Port als int)
    udp = UDP(dport=int(port))
    # fallback sport falls nicht gesetzt
    if not hasattr(udp, "sport") or udp.sport is None:
        udp.sport = 12345

    payload = "Test Payload"
    return ip_layer / udp / Raw(load=payload.encode() if isinstance(payload, str) else payload)

def main():
    p = argparse.ArgumentParser(description="Send simple IP packets with Scapy")
    p.add_argument("--dst", required=True, help="Zieladresse (IPv4 oder IPv6)")
    p.add_argument("--port", required=True, help="Zielport")
    p.add_argument("--iface", required=False, help="Interface to send through (z. B. wg0)", default=None)
    p.add_argument("--src", required=False, help="optional: Quell-IP (IPv4 oder IPv6)", default=None)
    p.add_argument("--count", type=int, default=1, help="Anzahl der Pakete")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    # Basic sanity checks
    try:
        pkt = build_pkt(args.dst, args.port, args.src)
    except ValueError as e:
        print(f"Fehler: {e}", file=sys.stderr)
        sys.exit(2)

    if args.verbose:
        print(f"Sending Packet to {args.dst}:{args.port}")
        if args.iface:
            print(f"Using iface: {args.iface}; src={args.src}")
        pkt.show()

    # send() verwendet L3-routing; iface kann angegeben werden (z.B. wg0)
    send(pkt, iface=args.iface, count=args.count, verbose=args.verbose)

if __name__ == "__main__":
    main()
