#!/usr/bin/env python3
"""Tiny local SCION bootstrap server used only by the test environment."""
from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TRC_RE = re.compile(r"ISD(?P<isd>\d+)-B(?P<base>\d+)-S(?P<serial>\d+)", re.I)


def load(as_dir: Path):
    topology = json.loads((as_dir / "topology.json").read_text())
    trcs = []
    blobs = {}
    certs = as_dir / "certs"
    if certs.is_dir():
        for p in sorted(certs.glob("*.trc")):
            m = TRC_RE.fullmatch(p.stem)
            if not m:
                continue
            isd, base, serial = map(int, (m.group("isd"), m.group("base"), m.group("serial")))
            ident = f"isd{isd}-b{base}-s{serial}"
            trcs.append({"id": {"isd": isd, "base_number": base, "serial_number": serial}})
            blobs[ident] = p.read_bytes()
    return topology, trcs, blobs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("directory", type=Path)
    ap.add_argument("bind")
    ap.add_argument("port", type=int)
    args = ap.parse_args()
    topology, trcs, blobs = load(args.directory)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *values):
            print(f"bootstrap: {self.address_string()} - {fmt % values}", flush=True)

        def send_body(self, status, body: bytes, ctype: str):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            if self.path == "/topology":
                self.send_body(200, json.dumps(topology, indent=2).encode(), "application/json")
                return
            if self.path == "/trcs":
                self.send_body(200, json.dumps(trcs, indent=2).encode(), "application/json")
                return
            m = re.fullmatch(r"/trcs/(isd\d+-b\d+-s\d+)(?:/blob)?", self.path, re.I)
            if m:
                ident = m.group(1).lower()
                if ident not in blobs:
                    self.send_error(404)
                    return
                if self.path.endswith("/blob"):
                    self.send_body(200, blobs[ident], "text/plain")
                else:
                    self.send_body(200, b"{}", "application/json")
                return
            self.send_error(404)

    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"Serving {topology.get('isd_as', 'unknown AS')} on http://{args.bind}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
