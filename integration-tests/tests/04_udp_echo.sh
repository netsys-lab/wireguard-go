#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${TARGET_IP:-}" ]]; then
    echo "TARGET_IP not set"
    exit 1
fi

rm -f /tmp/udp_received.txt

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f /tmp/udp_received.txt
}
trap cleanup EXIT

# Start a UDP echo server (nc) in ScitraServer in the background
# We pipe it to a file. nc -u -l won't exit on its own.
ip netns exec ScitraServer nc -u -l -p 32002 > /tmp/udp_received.txt &
SERVER_PID=$!
sleep 1

# Send a string via UDP from Client
echo "SCION-UDP-ECHO-TEST" | ip netns exec Client nc -u -w 2 "$TARGET_IP" 32002

# Give it a tiny bit of time to flush
sleep 0.5

# Kill the listening server to force it to flush its stdout buffer
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
SERVER_PID=""

# Verify the string was received
grep -q "SCION-UDP-ECHO-TEST" /tmp/udp_received.txt
