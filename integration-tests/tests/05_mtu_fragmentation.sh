#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${TARGET_IP:-}" ]]; then
    echo "TARGET_IP not set" >&2
    exit 1
fi

PORT=32004

# 2. Run test: MTU IP Fragmentation / PMTUD
# Send a single ICMP packet with a payload of 1450 bytes.
# Since WireGuard's MTU is 1420, this forces the IP layer to fragment the packet before it reaches the translator.
# The translator should reject fragments and synthesize an ICMPv6 Packet Too Big (PTB) with MTU 1280.
ip netns exec Client ping -c 1 -W 2 -s 1450 "$TARGET_IP" || true

# 3. Verify PMTUD updated the routing cache
ROUTE_MTU=$(ip netns exec Client ip -6 route get "$TARGET_IP" | grep -o 'mtu [0-9]*' | awk '{print $2}')
if [[ "$ROUTE_MTU" != "1280" ]]; then
    echo "PMTUD failure: Expected route cache MTU to be 1280, got '$ROUTE_MTU'"
    exit 1
fi
echo "PMTUD successfully updated route cache to MTU 1280"

