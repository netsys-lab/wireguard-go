"""
###[ IP ]###
  version   = 4
  ihl       = 5
  tos       = 0x0
  len       = 146
  id        = 25766
  flags     = DF
  frag      = 0
  ttl       = 64
  proto     = udp
  chksum    = 0xd79a
  src       = 127.0.0.25
  dst       = 127.0.0.1
  \options   \
###[ UDP ]###
     sport     = 31006
     dport     = 32767
     len       = 126
     chksum    = 0xfea9
###[ SCION ]###
        version   = 0
        qos       = 0x0
        fl        = 0x1
        nh        = SCMP
        hlen      = 26
        plen      = 14
        ptype     = SCION
        dt        = IP
        dl        = 0
        st        = IP
        sl        = 0
        reserved  = 0
        dst_isd   = 1
        dst_asn   = 64513
        src_isd   = 1
        src_asn   = 64514
        dst_host  = 127.0.0.1
        src_host  = 127.0.0.2
        \path      \
         |###[ SCION Path ]###
         |  curr_inf  = 1
         |  curr_hf   = 3
         |  reserved  = 0
         |  seg0_len  = 2
         |  seg1_len  = 2
         |  seg2_len  = 0
         |  \info_fields\
         |   |###[ Info Field ]###
         |   |  flags     = 
         |   |  reserved  = 0
         |   |  segid     = 0xf20b
         |   |  timestamp = 2026-04-20 21:20:41
         |   |###[ Info Field ]###
         |   |  flags     = C
         |   |  reserved  = 0
         |   |  segid     = 0xad3a
         |   |  timestamp = 2026-04-20 21:20:15
         |  \hop_fields\
         |   |###[ Hop Field ]###
         |   |  flags     = 
         |   |  exp_time  = 6:00:00
         |   |  cons_ingress= 2
         |   |  cons_egress= 0
         |   |  mac       = 0xa577b9355991
         |   |###[ Hop Field ]###
         |   |  flags     = 
         |   |  exp_time  = 6:00:00
         |   |  cons_ingress= 0
         |   |  cons_egress= 4
         |   |  mac       = 0x7d3e9fc3ef14
         |   |###[ Hop Field ]###
         |   |  flags     = 
         |   |  exp_time  = 6:00:00
         |   |  cons_ingress= 0
         |   |  cons_egress= 2
         |   |  mac       = 0x8321f8c373b0
         |   |###[ Hop Field ]###
         |   |  flags     = 
         |   |  exp_time  = 6:00:00
         |   |  cons_ingress= 2
         |   |  cons_egress= 0
         |   |  mac       = 0xe3d771f98f65
###[ SCMP ]###
           type      = 129
           code      = 0
           chksum    = 0xe429
           \message   \
            |###[ Echo Reply ]###
            |  id        = 32767
            |  seq       = 0
###[ Raw ]###
              load      = b'Hello!'

"""
   
from datetime import datetime, timezone
from pathlib import Path
from scapy.layers.inet import IP
from scapy.all import Raw

from scapy_scion.layers.scion import (
    UDP,
    SCION,
    SCIONPath,
    InfoField,
    HopField,
)
from scapy_scion.layers.scmp import SCMP, ScmpEchoReply

from tests import write_packets

pkt = (
    IP(
        src="127.0.0.25",
        dst="127.0.0.1",
        id=25766,
        flags="DF",
        ttl=64,
        proto="udp",
        len=146,
        chksum=0xD79A,
    )
    / UDP(
        sport=31006,
        dport=32767,
        len=126,
        chksum=0xFEA9,
    )
    / SCION(
        version=0,
        qos=0x0,
        fl=0x1,
        nh="SCMP",
        hlen=26,
        plen=14,
        ptype="SCION",
        dt="IP",
        dl=0,
        st="IP",
        sl=0,
        dst_isd=1,
        dst_asn=64513,
        src_isd=1,
        src_asn=6451,
        dst_host="127.0.0.1",
        src_host="127.0.0.2",
        path=SCIONPath(
            curr_inf=1,
            curr_hf=3,
            seg0_len=2,
            seg1_len=2,
            seg2_len=0,
            info_fields=[
                InfoField(
                    flags=0,
                    segid=0xF20B,
                    timestamp=datetime(2026, 4, 20, 21, 20, 41, tzinfo=timezone.utc),
                ),
                InfoField(
                    flags="C",
                    segid=0xAD3A,
                    timestamp=datetime(2026, 4, 20, 21, 20, 15, tzinfo=timezone.utc),
                ),
            ],
            hop_fields=[
                HopField(
                    flags=0,
                    exp_time=63,
                    cons_ingress=2,
                    cons_egress=0,
                    mac=0xA577B9355991,
                ),
                HopField(
                    flags=0,
                    exp_time=63,
                    cons_ingress=0,
                    cons_egress=4,
                    mac=0x7D3E9FC3EF14,
                ),
                HopField(
                    flags=0,
                    exp_time=63,
                    cons_ingress=0,
                    cons_egress=2,
                    mac=0x8321F8C373B0,
                ),
                HopField(
                    flags=0,
                    exp_time=63,
                    cons_ingress=2,
                    cons_egress=0,
                    mac=0xE3D771F98F65,
                ),
            ],
        ),
    )
    / SCMP(
        type=129,
        code=0,
        chksum=0xE429,
        message=ScmpEchoReply(
            id=32767,
            seq=0,
        ),
    )
    / Raw(b"Hello!")
)

pkt.show()

del pkt[IP].len
del pkt[IP].chksum
del pkt[UDP].len
del pkt[UDP].chksum
del pkt[SCMP].chksum

bin_path = Path(__file__).with_suffix(".bin")
write_packets(pkt, bin_path)

from scapy.utils import wrpcap

pcap_path = str(Path(__file__).with_suffix(".pcap"))
wrpcap(pcap_path, pkt)