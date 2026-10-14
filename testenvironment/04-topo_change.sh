#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
check_root

log_step "Patch namespace-facing SCION addresses"
create_directories

OUT_ENV="$(runtime_env_file)"
python3 "$TESTENV_DIR/tools/patch_topology.py" \
  --scion-dir "$SCION_DIR" \
  --source-asn "$SOURCE_ASN" \
  --target-asn "$TARGET_ASN" \
  --source-br-primary "${WG_SERVER_IP%%/*}" \
  --source-daemon-ip "$SOURCE_DAEMON_IP" \
  --source-control-ip "$SOURCE_CONTROL_IP" \
  --target-br-first "$SCITRA_BR_FIRST_IP" \
  --target-daemon-ip "$SCITRA_DAEMON_IP" \
  --out-env "$OUT_ENV"

source "$OUT_ENV"

# Source daemon is reachable from Client through WireGuard once wg-server exists.
ip netns exec "$SERVER_NS" ip addr add "$SOURCE_DAEMON_IP/32" dev lo 2>/dev/null || true

# The source Control/Discovery Service address itself is placed on wg-server in
# 06-wireguard.sh, because that interface does not exist yet in this step.
# topology-runtime.env already contains SOURCE_CONTROL_ADDR for later checks.

# Target BR internal addresses must already exist before ./scion.sh run so the
# routers can bind to them. They all live on the Server side of the Scitra veth.
for ipaddr in "${TARGET_BR_IPS[@]}"; do
    ip netns exec "$SERVER_NS" ip addr add "$ipaddr/32" dev "$SCITRA_SERVER_IFACE" 2>/dev/null || true
done

log_success "Topology patched. Runtime addresses written to $OUT_ENV"
