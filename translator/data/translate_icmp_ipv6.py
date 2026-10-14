from pathlib import Path
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6DestUnreach
from scapy_scion.layers.scion import SCION, SCIONPath, InfoField, HopField
from scapy.layers.l2 import Dot1Q
from scapy.all import Packet, XByteField, ShortField, IntField, StrLenField, PacketField, bind_layers
from tests import write_packets

class SCMPPacket(Packet):
    name = "SCMP"
    fields_desc = [
        XByteField("type", 0),
        XByteField("code", 0),
        ShortField("chksum", 0),
    ]

bind_layers(IPv6, SCMPPacket, nh=0x3c)  # SCMP next header = 60

icmp_payload = b"Hello SCION"

icmp6_echo_request = IPv6(
    tc=0,
    fl=0x123,
    hlim=64,
    src="fc00:10fc:0100::2",
    dst="fc00:10fc:0100::1"
) / ICMPv6EchoRequest(
    id=0x1234,
    seq=1
) / icmp_payload

icmp6_echo_reply = IPv6(
    tc=0,
    fl=0x123,
    hlim=64,
    src="fc00:10fc:0100::1",
    dst="fc00:10fc:0100::2"
) / ICMPv6EchoReply(
    id=0x1234,
    seq=1
) / icmp_payload

icmp6_dest_unreach = IPv6(
    tc=0,
    fl=0x456,
    hlim=64,
    src="fc00:10fc:0100::1",
    dst="fc00:10fc:0100::2"
) / ICMPv6DestUnreach(
    code=1
) / icmp_payload

from datetime import datetime

path = SCIONPath(
    curr_inf=1,
    curr_hf=1,
    seg0_len=2,
    seg1_len=0,
    seg2_len=0,
    info_fields=[
        InfoField(flags="", segid=1, timestamp=datetime(2025, 1, 1, 0, 0, 0)),
    ],
    hop_fields=[
        HopField(cons_ingress=1, cons_egress=2),
        HopField(cons_ingress=2, cons_egress=0),
    ]
)

scmp_echo_request = IPv6(
    tc=0,
    fl=0x123,
    hlim=64,
    src="fc00:10fc:0100::2",
    dst="::1"
) / SCION(
    qos=0,
    fl=0x123,
    dst_isd=1,
    dst_asn="64513",
    src_isd=1,
    src_asn="64513",
    dst_host="fc00:10fc:0100::1",
    src_host="fc00:10fc:0100::2",
    path=path
) / SCMPPacket(
    type=0x80,
    code=0x00
) / icmp_payload

scmp_echo_reply = IPv6(
    tc=0,
    fl=0x123,
    hlim=64,
    src="fc00:10fc:0100::1",
    dst="::1"
) / SCION(
    qos=0,
    fl=0x123,
    dst_isd=1,
    dst_asn="64513",
    src_isd=1,
    src_asn="64513",
    dst_host="fc00:10fc:0100::2",
    src_host="fc00:10fc:0100::1",
    path=path
) / SCMPPacket(
    type=0x81,
    code=0x00
) / icmp_payload

write_packets(
    [icmp6_echo_request, icmp6_echo_reply, icmp6_dest_unreach, scmp_echo_request, scmp_echo_reply],
    Path(__file__).with_suffix(".bin")
)
print(f"Written test packets to {Path(__file__).with_suffix('.bin')}")