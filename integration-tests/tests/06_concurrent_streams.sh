#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${TARGET_IP:-}" ]]; then
    echo "TARGET_IP not set" >&2
    exit 1
fi

PORT=32003

# Cleanup handler for any script exit (errors, INT, TERM)
cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# 1. Start iperf3 server in background
ip netns exec ScitraServer iperf3 -s -p "$PORT" -1 &
SERVER_PID=$!

sleep 0.5

# 2. Run test: Concurrent Streams (Port Multiplexing / NAT table concurrency)
# -P 8: 8 parallel streams
ip netns exec Client iperf3 -c "$TARGET_IP" -p "$PORT" -P 8 -n 1M

wait "$SERVER_PID" 2>/dev/null || true
