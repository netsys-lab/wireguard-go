#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${TARGET_IP:-}" ]]; then
    echo "TARGET_IP not set"
    exit 1
fi

ORIG_MTU=$(ip netns exec Client ip link show wg-client | grep -o 'mtu [0-9]*' | awk '{print $2}' || echo "1420")

# Cleanup handler for any script exit (errors, INT, TERM)
cleanup() {
    ip netns exec Client ip link set dev wg-client mtu "$ORIG_MTU" 2>/dev/null || true
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Temporarily increase MTU to 1500 to bypass MSS clamping and force dynamic PMTUD
ip netns exec Client ip link set dev wg-client mtu 1500

# Start iperf3 server in ScitraServer in the background
ip netns exec ScitraServer iperf3 -s -p 32001 -1 &
SERVER_PID=$!

# Wait for server to start
sleep 0.5

# Run iperf3 client from Client namespace
# Send 2MB of data (-n 2M) to test TCP Throughput and Path MTU Discovery
ip netns exec Client iperf3 -c "$TARGET_IP" -p 32001 -n 2M

wait "$SERVER_PID" 2>/dev/null || true
