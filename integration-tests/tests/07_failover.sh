#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${TARGET_IP:-}" ]]; then
    echo "TARGET_IP not set"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTENV_DIR="$(realpath "$SCRIPT_DIR/../../testenvironment")"
source "$TESTENV_DIR/config.sh"

cleanup() {
    (cd "$SCION_DIR" && ./tools/supervisor.sh mstart as1-64512:br1-64512-1 2>/dev/null || true)
}
trap cleanup EXIT

echo "Stopping border router br1-64512-1..."
(cd "$SCION_DIR" && ./tools/supervisor.sh mstop as1-64512:br1-64512-1)

# Wait a moment for SCION path failover
sleep 5

# Test if we can still ping (traffic should take an alternate path)
ip netns exec Client ping -c 3 -W 2 "$TARGET_IP"
