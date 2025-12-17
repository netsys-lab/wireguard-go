from scapy_scion.layers.scion import SCION
from scapy.all import Ether, IP, TCP, wrpcap
import os

def create_ip_packet(filename, src, dst, sport=5555, dport=80, payload=b"Payload"):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / payload
    
    # Save Package
    #wrpcap(f"packets/ip_packets/{filename}.pcap", [pkt])

    # Write the bytes
    with open(f"packets/ip_packets/{filename}.bin", "wb") as f:
        f.write(bytes(pkt))

    return pkt

def create_scion_packet(filename, src_scion, dst_scion, src_host, dst_host, sport=5555, dport=80, payload=b"Payload"):
    pkt = SCION()
    # Using Fixed Scion ISD-AS Values
    # ToDo: Add the correct ISD-AS Values for a given IP Adress
    #src=SCIONAddr(f"1-ff00:0:111,[{src_host}]"),
    #dst=SCIONAddr(f"1-ff00:0:112,[{dst_host}]")
    pkt.PathType = b'0'
    pkt.Path = b''
    pkt.src=f"{src_scion},[{src_host}]",
    pkt.dst=f"{dst_scion},[{dst_host}]"
    pkt /= Ether()/IP()/TCP(sport=sport, dport=dport) / payload
    #wrpcap(f"packets/scion_packets/{filename}.pcap", [pkt])

    # Write the bytes
    with open(f"packets/scion_packets/{filename}.bin", "wb") as f:
        f.write(bytes(pkt))

    return pkt


if __name__ == "__main__":
    
    #print(dir(scion)) # Display available packages

    os.makedirs("packets/ip_packets", exist_ok=True)

    create_ip_packet("test1", "192.0.2.1", "192.0.2.2")
    #create_scion_packet("test1", "1-ff00:0:111", "1-ff00:0:112", "192.0.2.1", "192.0.2.2")
    