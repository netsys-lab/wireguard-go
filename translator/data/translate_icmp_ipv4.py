from pathlib import Path
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy_scion.layers.scion import UDP, SCION, SCMP, SCMPDestinationUnreachable
from tests import write_packets


payload = b"TEST"

# ICMPv6 Echo Request
icmpv6 = IPv6(
    tc = 32,
    fl = 0x86c8b,
    hlim = 64,
    src = "fc00:10fb:f000::ffff:a00:1",
    dst = "fc00:20fb:f100::ffff:a00:2"
)

# SCMP Destination Unreachable message
scmp = IP(
    tos = 32,
    ttl = 64,
    id = 0,
    flags = "DF",
    frag = 0,
    src = "10.0.0.1",
    dst = "127.0.0.9"
) / UDP(
    sport = 32766,
    dport = 31002
) / SCION(
    qos = 32,
    fl = 0x86c8b,
    dst_isd = 2,
    dst_asn = "64497",
    src_isd = 1,
    src_asn = "64496",
    dst_host = "10.0.0.2",
    src_host = "10.0.0.1",
) / SCMP(
    type_ = 1,  # Destination Unreachable
    code = 0,   # No route to destination
) / SCMPDestinationUnreachable() / payload

write_packets([icmpv6, scmp], Path(__file__).with_suffix(".bin"))
