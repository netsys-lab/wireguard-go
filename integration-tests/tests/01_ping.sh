#!/usr/bin/env bash
set -euo pipefail

# Ensure TARGET_IP is set by the runner
if [[ -z "${TARGET_IP:-}" ]]; then
    echo "TARGET_IP not set"
    exit 1
fi

# As the very first test in the suite, this test acts as the Basic Connectivity
# and Path Discovery test. SCION paths can take several seconds to fully converge
# and propagate across the ASes in slower CI environments.
# We ping repeatedly for up to 30 seconds until the path is active and we get a reply.
echo "Waiting for SCION paths to become active..."
for i in {1..15}; do
    if ip netns exec Client ping -c 1 -W 1 "$TARGET_IP" >/dev/null 2>&1; then
        echo "Path is active and basic connectivity established! Ping successful."
        exit 0
    fi
    sleep 2
done

echo "Timeout waiting for SCION path."
ip netns exec Client ping -c 3 -W 2 "$TARGET_IP"
exit 1
