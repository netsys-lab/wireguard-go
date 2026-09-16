#!/usr/bin/env bash
set -euo pipefail

# Ensure TARGET_IP is set by the runner
if [[ -z "${TARGET_IP:-}" ]]; then
    echo "TARGET_IP not set"
    exit 1
fi

# Ping the SCION translated IPv6 address from the Client namespace
# -c 3: Send 3 packets
# -W 2: 2 seconds timeout for response
# Exit code 0 means at least one response was received
ip netns exec Client ping -c 3 -W 2 "$TARGET_IP"
