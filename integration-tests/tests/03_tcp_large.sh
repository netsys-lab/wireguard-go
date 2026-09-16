#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${TARGET_IP:-}" ]]; then
    echo "TARGET_IP not set"
    exit 1
fi

# Start iperf3 server in ScitraServer in the background
ip netns exec ScitraServer iperf3 -s -p 32001 -1 &
SERVER_PID=$!

# Wait for server to start
sleep 1

# Run iperf3 client from Client namespace
# Send 1MB of data (-n 1M) to test large packets and MTU fragmentation
if ! ip netns exec Client iperf3 -c "$TARGET_IP" -p 32001 -n 1M; then
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

wait $SERVER_PID
