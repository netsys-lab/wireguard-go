#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
check_root

ASDIR="$SCION_DIR/gen/$BOOTSTRAP_AS"

start_bootstrap() {
    [[ -f "$ASDIR/topology.json" ]] || { log_error "Bootstrap AS config missing: $ASDIR"; return 1; }
    ip netns exec "$SERVER_NS" pkill -f "$BOOTSTRAP_PY" 2>/dev/null || true
    ip netns exec "$SERVER_NS" bash -c "nohup python3 '$BOOTSTRAP_PY' '$ASDIR' '$BOOTSTRAP_BIND' '$BOOTSTRAP_PORT' > '$LOGS_DIR/bootstrap.log' 2>&1 & echo \$! > '$STATE_DIR/bootstrap.pid'"
    wait_for 10 "bootstrap server" "ip netns exec '$SERVER_NS' curl -fsS 'http://$BOOTSTRAP_BIND:$BOOTSTRAP_PORT/topology'"
    log_success "Bootstrap server ready: http://$BOOTSTRAP_BIND:$BOOTSTRAP_PORT"
}

case "${1:-}" in
    up) log_step "Bootstrap server"; start_bootstrap ;;
    down) ip netns exec "$SERVER_NS" pkill -f "$BOOTSTRAP_PY" 2>/dev/null || true; rm -f "$STATE_DIR/bootstrap.pid" ;;
    status) ip netns exec "$SERVER_NS" ss -lntp 2>/dev/null | grep ":$BOOTSTRAP_PORT" || true ;;
    logs) tail -100 "$LOGS_DIR/bootstrap.log" 2>/dev/null || true ;;
    *) echo "Usage: $0 {up|down|status|logs}"; exit 2 ;;
esac
