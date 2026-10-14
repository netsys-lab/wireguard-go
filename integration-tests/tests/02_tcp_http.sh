#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${TARGET_IP:-}" ]]; then
    echo "TARGET_IP not set"
    exit 1
fi

# Fetch the HTTP page from the target Scitra-TUN instance
# --fail: Return error on server errors (404, 500)
# --max-time: Timeout after 5 seconds
ip netns exec Client curl -g -6 --fail --max-time 5 -sS "http://[$TARGET_IP]:8000/" | grep -q "This page was delivered through Scitra-TUN"
