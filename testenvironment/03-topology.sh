#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
check_root

generate() {
    [[ -x "$SCION_DIR/scion.sh" ]] || { log_error "SCION not set up at $SCION_DIR. Run the main testenvironment script first."; return 1; }
    [[ -f "$SCION_TOPOLOGY" ]] || { log_error "Topology file missing: $SCION_TOPOLOGY"; return 1; }

    log_info "Generating topology from $SCION_TOPOLOGY"

    # SCION's supervisor helper hard-codes /tmp/supervisor.sock. Clean a stale
    # socket/pidfile before scion.sh topology calls its own stop/topo-clean path.
    # This prevents a previous namespace run from producing a misleading
    # "unix:///tmp/supervisor.sock refused connection" on the next startup.
    bash "$SCRIPT_DIR/07-scion.sh" prepare

    # Keep the same runtime ownership model as the original testenvironment:
    # testenvironment.bash is started with sudo, therefore scion.sh topology,
    # topo-clean, run and stop all execute as root. This keeps generated gen/
    # and gen-cache/ files consistently owned and avoids mixed-owner cleanup
    # failures between subsequent runs.
    (
        cd "$SCION_DIR"
        ./scion.sh topology -c "$SCION_TOPOLOGY"
    )

    [[ -d "$SCION_DIR/gen/AS$SOURCE_ASN" ]] || { log_error "Missing generated source AS directory AS$SOURCE_ASN"; return 1; }
    [[ -d "$SCION_DIR/gen/AS$TARGET_ASN" ]] || { log_error "Missing generated target AS directory AS$TARGET_ASN"; return 1; }
    log_success "SCION topology generated"
}

clean() {
    [[ -x "$SCION_DIR/scion.sh" ]] || return 0
    log_info "Cleaning generated SCION topology/runtime state in $SCION_DIR"
    (
        cd "$SCION_DIR"
        ./scion.sh topo-clean
    ) || true
}

status() {
    ls -d "$SCION_DIR/gen/AS"* 2>/dev/null || true
    [[ -f "$SCION_DIR/gen/sciond_addresses.json" ]] && cat "$SCION_DIR/gen/sciond_addresses.json" || true
}

case "${1:-}" in
    generate) log_step "SCION topology"; generate ;;
    clean) clean ;;
    status) status ;;
    *) echo "Usage: $0 {generate|clean|status}"; exit 2 ;;
esac
