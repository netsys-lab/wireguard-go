#!/bin/env python3
# Copyright (c) 2024-2026 Lars-Christian Schulz

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import email
import http.server
import json
import re
import time
from http import HTTPStatus
from pathlib import Path
from typing import Dict, Tuple


class RequestHandler(http.server.BaseHTTPRequestHandler):

    server_version = "TrivialBootstrapServer/0.1"

    def __init__(self, *args, data, **kwargs):
        self.data = data
        super().__init__(*args, **kwargs)

    def do_GET(self) -> None:
        content = self.send_head()
        if content:
            self.wfile.write(content)

    def do_HEAD(self) -> None:
        self.send_head()

    def send_head(self) -> bytes:
        try:
            ctype, content = self.data[self.path]
        except KeyError:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None

        if ctype == "application/json":
            encoded_content = json.dumps(content, indent=4).encode()
        else:
            encoded_content = content.encode()

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", len(encoded_content))
        self.send_header("Last-Modified",
            email.utils.formatdate(time.time(), usegmt=True))
        self.end_headers()

        return encoded_content


def parse_trc_name(name: str) -> Tuple[int, int, int]:
    m = re.match(r"ISD(\d)+-B(\d)+-S(\d)+", name)
    if not m:
        raise ValueError()
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def load_files(directory: Path) -> Dict:
    data = {}
    with open(directory / "topology.json", "rt") as file:
        data["/topology"] = ("application/json", json.load(file))

    data["/trcs"] = ("application/json", [])
    for trc in (directory / "certs").glob("*.trc"):
        if not trc.is_file():
            continue
        try:
            isd, base, serial = parse_trc_name(trc.stem)
        except ValueError:
            continue
        data["/trcs"][1].append({"id": {
            "isd": isd,
            "base_number": base,
            "serial_number": serial,
        }})
        data[f"/trcs/isd{isd}-b{base}-s{serial}"] = ("application/json", {})
        data[f"/trcs/isd{isd}-b{base}-s{serial}/blob"] = ("text/plain", trc.read_text())

    return data


def main():
    parser = argparse.ArgumentParser(description="Simple SCION end host bootstrap server.")
    parser.add_argument("directory", type=Path, help="Path to AS configuration directory")
    parser.add_argument("bind", help="Bind address")
    parser.add_argument("port", type=int, help="Server port")
    args = parser.parse_args()

    data = load_files(args.directory)

    class HTTPServer(http.server.HTTPServer):
        def finish_request(self, request, client_address):
            self.RequestHandlerClass(request, client_address, self, data=data)

    addr = (args.bind, args.port)
    with HTTPServer(addr, RequestHandler) as httpd:
        host, port = httpd.socket.getsockname()[:2]
        host_url = f"[{host}]" if ":" in host else host
        print(f"Serving topology of AS {data['/topology'][1]['isd_as']} at http://{host_url}:{port}")

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nExiting")
            return


if __name__ == "__main__":
    main()