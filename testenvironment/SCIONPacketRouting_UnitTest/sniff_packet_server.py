#!/usr/bin/env python3
"""
sniff_server.py
=============
Snifft auf allen Server-Interfaces.
Läuft bis es mit Ctrl+C beendet wird.

Usage:
    ip netns exec Server /var/lib/venv-scapy/bin/python sniff_server.py

Output:
    - Terminal (print)
    - Log-Datei (logs/sniff_server.log)
"""

import time
import os
from scapy.all import *

# Log-Verzeichnis
LOG_DIR = os.path.dirname(os.path.abspath(__file__)) + "/logs"
LOG_FILE = LOG_DIR + "/sniff_server.log"

# Interfaces die gesnifft werden sollen
# Format: (interface_name, filter)
# BRs sind keine eigenen Interfaces - sie lauschen auf UDP-Ports auf loopback
#
# Netzwerk-Interfaces im Server Namespace:
#   - veth-server   (veth zu Client)
#   - wg-server    (WireGuard Interface)
#   - lo           (loopback)
#
# SCION Border Router (UDP-Ports auf lo):
#   - BR:31006     = AS64513 Border Router (127.0.0.25:31006)
#   - BR:31010     = AS64514 Border Router (127.0.0.33:31010)

INTERFACES = [
    # Normale Interfaces
    ("veth-server", None),
    ("wg-server", None),
    #("lo", "udp"),
    
    # BR als eigene "Interfaces" - sniff auf lo mit Port-Filter
    ("BR:31006", "port 31006"),    # AS64513 Border Router
    ("BR:31010", "port 31010"),    # AS64514 Border Router
    ("BR:31002", "port 31002"),    # AS64514 Border Router
]

# Detail-Level: "summary" oder "detail"
DETAIL = "summary"

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def handler(pkt, iface):
    ts = time.strftime("%H:%M:%S.%f")[:-3]
    # BR-Ports als eigene "Interfaces" anzeigen
    msg = f"[Server:{iface}] {ts} >> {pkt.summary()}"
    
    if DETAIL == "detail":
        log(f"[Server:{iface}] ===========================")
        log(f"[Server:{iface}] {pkt.summary()}")
        log(f"[Server:{iface}] --- Details ---")
        try:
            pkt.show(out=log)
        except:
            pass
    else:
        log(msg)

def main():
    # Log-Datei erstellen
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, "w") as f:
        f.write(f"# Server Sniffer Log - gestartet {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    log("=" * 50)
    log("Server Sniffer gestartet")
    log("Interfaces: " + ", ".join([i[0] for i in INTERFACES]))
    log("Log-Datei: " + LOG_FILE)
    log("Druecke Ctrl+C zum Beenden")
    log("=" * 50)

    import threading

    def sniff_one(logical_iface, real_iface, filter_str):
        # BR-Ports verwenden immer lo als reales Interface
        if filter_str:
            log(f"[*] Sniffing on {real_iface} (filter: {filter_str}) -> als {logical_iface}")
            sniff(iface=real_iface, filter=filter_str, prn=lambda p: handler(p, logical_iface), store=0)
        else:
            log(f"[*] Sniffing on {real_iface}")
            sniff(iface=real_iface, prn=lambda p: handler(p, logical_iface), store=0)

    threads = []
    for logical_iface, filter_str in INTERFACES:
        # Bestimme reales Interface
        if logical_iface.startswith("BR:") or logical_iface.startswith("DISP:") or logical_iface.startswith("ECHO:"):
            real_iface = "lo"  # BR/Dispatcher/Echo sind auf loopback
        else:
            real_iface = logical_iface
        
        t = threading.Thread(target=sniff_one, args=(logical_iface, real_iface, filter_str))
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        log("Stoppe Sniffer...")
        return

if __name__ == "__main__":
    main()