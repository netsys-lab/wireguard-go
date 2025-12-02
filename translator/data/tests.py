import struct
from typing import Iterable


def write_packets(pkts: Iterable, file_path: str):
    with open(file_path, "wb") as file:
        for pkt in pkts:
            b = bytes(pkt)
            file.write(struct.pack(">I", len(b)))
            file.write(b)