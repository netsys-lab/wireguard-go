#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
check_root

CURRENT_STEP="initialization"
trap 'rc=$?; log_error "Setup failed during: $CURRENT_STEP (exit $rc)"; echo "Logs: $LOGS_DIR" >&2; exit $rc' ERR

run_step() {
    CURRENT_STEP="$1"
    shift
    echo
    log_info "=== $CURRENT_STEP ==="
    "$@"
}

cmd_up() {
    create_directories

    run_step "0/9 Install/check dependencies" bash "$SCRIPT_DIR/00-dependencies.sh"

    print_config

    # Build the infrastructure from the outside in. The custom translator client
    # is intentionally the LAST component started.
    run_step "1/9 Create namespaces and veth links" bash "$SCRIPT_DIR/01-namespaces.sh" up
    run_step "2/9 Generate SCION ring topology" bash "$SCRIPT_DIR/03-topology.sh" generate
    run_step "3/9 Refresh custom wireguard-go build and keys" bash "$SCRIPT_DIR/02-build.sh" build
    run_step "4/9 Patch generated SCION addresses for namespace interfaces" bash "$SCRIPT_DIR/04-topo_change.sh"
    run_step "5/9 Start vanilla WireGuard server" bash "$SCRIPT_DIR/06-wireguard.sh" server-up
    run_step "6/9 Start and verify SCION infrastructure" bash "$SCRIPT_DIR/07-scion.sh" up
    run_step "7/9 Start source-AS bootstrap server" bash "$SCRIPT_DIR/05-bootstrap.sh" up
    run_step "8/9 Start target Scitra-TUN and verify with reference Scitra" bash "$SCRIPT_DIR/08-scitra-server.sh" up
    run_step "9/9 Start custom WireGuard / translator client (NO translation test)" bash "$SCRIPT_DIR/06-wireguard.sh" client-up

    echo
    bash "$SCRIPT_DIR/09-test.sh" summary || true
}

stop_runtime() {
    trap - ERR
    bash "$SCRIPT_DIR/08-scitra-server.sh" down 2>/dev/null || true
    bash "$SCRIPT_DIR/07-scion.sh" down 2>/dev/null || true
    bash "$SCRIPT_DIR/05-bootstrap.sh" down 2>/dev/null || true
    bash "$SCRIPT_DIR/06-wireguard.sh" down 2>/dev/null || true
    bash "$SCRIPT_DIR/01-namespaces.sh" down 2>/dev/null || true
}

cmd_down() {
    log_step "Stop test environment"
    stop_runtime
    log_success "Environment stopped and namespaces removed. Cached dependencies remain in $DEPS_DIR"
    log_info "Logs remain in $LOGS_DIR"
}

cmd_clean() {
    log_step "Clean generated test state"
    stop_runtime
    bash "$SCRIPT_DIR/03-topology.sh" clean 2>/dev/null || true
    rm -rf "$RUNTIME_DIR"
    log_success "Runtime and generated SCION topology state removed; dependency/source checkouts kept"
}

cmd_purge() {
    log_step "Purge local test-owned dependencies"
    stop_runtime
    bash "$SCRIPT_DIR/03-topology.sh" clean 2>/dev/null || true
    rm -rf "$RUNTIME_DIR" "$DEPS_DIR"
    log_success "Removed .runtime and testenvironment-owned .deps"
}

cmd_uninstall() {
    log_step "Fully uninstall testenvironment runtime state"
    stop_runtime
    bash "$SCRIPT_DIR/03-topology.sh" clean 2>/dev/null || true
    rm -rf "$RUNTIME_DIR" "$DEPS_DIR" "$INSTALL_STATE_DIR"
    log_success "Removed runtime and testenvironment-owned cached dependencies"
}

cmd_status() {
    bash "$SCRIPT_DIR/01-namespaces.sh" status 2>/dev/null || true
    bash "$SCRIPT_DIR/06-wireguard.sh" status 2>/dev/null || true
    bash "$SCRIPT_DIR/07-scion.sh" status 2>/dev/null || true
    bash "$SCRIPT_DIR/08-scitra-server.sh" status 2>/dev/null || true
    bash "$SCRIPT_DIR/09-test.sh" summary 2>/dev/null || true
}

cmd_test() { bash "$SCRIPT_DIR/09-test.sh" test; }

usage() {
    cat <<EOF2
Usage:
  sudo ./testenvironment.bash           # same as 'up'
  sudo ./testenvironment.bash up        # recreate/start the complete debug environment
  sudo ./testenvironment.bash test      # ONLY here: run our translator end-to-end test
  sudo ./testenvironment.bash status
  sudo ./testenvironment.bash down      # stop + remove namespaces; KEEP .deps and logs
  sudo ./testenvironment.bash clean     # down + remove runtime/generated topology; KEEP .deps
  sudo ./testenvironment.bash purge     # down + remove .runtime/.deps
  sudo ./testenvironment.bash uninstall # purge all runtime state

Optional debugging packages:
  sudo INSTALL_DEBUG_TOOLS=1 ./testenvironment.bash

Fresh clone workflow:
  git clone <OUR-REPO>
  cd <OUR-REPO>/testenvironment
  chmod +x testenvironment.bash
  sudo SCION_DIR=/path/to/scion ./testenvironment.bash
EOF2
}

case "${1:-up}" in
    up) cmd_up ;;
    down) cmd_down ;;
    clean) cmd_clean ;;
    purge) cmd_purge ;;
    uninstall|remove) cmd_uninstall ;;
    status) cmd_status ;;
    test) cmd_test ;;
    help|-h|--help) usage ;;
    *) usage; exit 2 ;;
esac
