#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${TARGET_IP:-}" ]]; then
    echo "TARGET_IP not set"
    exit 1
fi

# Start a UDP echo server (nc) in ScitraServer in the background
# -u: UDP, -l: listen, -p: port
ip netns exec ScitraServer nc -u -l -p 32002 > /tmp/udp_received.txt &
SERVER_PID=$!
sleep 1

# Send a string via UDP from Client
echo "SCION-UDP-ECHO-TEST" | ip netns exec Client nc -u -w 2 "$TARGET_IP" 32002

# Kill the listening server (since nc -l -u usually stays open)
kill $SERVER_PID 2>/dev/null || true

# Verify the string was received
grep -q "SCION-UDP-ECHO-TEST" /tmp/udp_received.txt
