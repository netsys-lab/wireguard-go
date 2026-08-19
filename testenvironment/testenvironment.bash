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

    # Dependency setup can select a managed/external SCION checkout and Go.
    if [[ -f "$SCION_STATE_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$SCION_STATE_FILE"
        export SCION_SOURCE SCION_DIR
    fi
    if [[ -f "$GO_STATE_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$GO_STATE_FILE"
        export GO_SOURCE GO_BIN
    fi

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
    if [[ "$SCION_SOURCE" == "managed" ]]; then rm -f "$SCION_STATE_FILE"; fi
    if [[ "${GO_SOURCE:-}" == "managed" ]]; then rm -f "$GO_STATE_FILE"; fi
    log_success "Removed .runtime and testenvironment-owned .deps"
    if [[ "$SCION_SOURCE" == "external" ]]; then
        log_info "External SCION source checkout was not deleted: $SCION_DIR"
    fi
    log_info "System Go and APT packages are intentionally kept"
}

restore_system_go_if_owned() {
    [[ -f "$SYSTEM_GO_MARKER" ]] || return 0

    local SYSTEM_GO_BACKUP_DIR="" SYSTEM_GO_BIN_BACKUP="" SYSTEM_GOFMT_BIN_BACKUP=""
    if [[ -f "$SYSTEM_GO_STATE_FILE" ]]; then
        # shellcheck disable=SC1090
        source "$SYSTEM_GO_STATE_FILE"
    fi

    log_info "Reverting system-wide Go installed by this testenvironment..."
    if [[ "$(readlink -f /usr/local/bin/go 2>/dev/null || true)" == "$SYSTEM_GO_DIR/bin/go" ]]; then rm -f /usr/local/bin/go; fi
    if [[ "$(readlink -f /usr/local/bin/gofmt 2>/dev/null || true)" == "$SYSTEM_GO_DIR/bin/gofmt" ]]; then rm -f /usr/local/bin/gofmt; fi
    [[ -f "$SYSTEM_GO_PROFILE" ]] && rm -f "$SYSTEM_GO_PROFILE"
    rm -rf "$SYSTEM_GO_DIR"

    if [[ -n "$SYSTEM_GO_BACKUP_DIR" && -e "$SYSTEM_GO_BACKUP_DIR" ]]; then
        mv "$SYSTEM_GO_BACKUP_DIR" "$SYSTEM_GO_DIR"
        log_info "Restored previous $SYSTEM_GO_DIR"
    fi
    if [[ -n "$SYSTEM_GO_BIN_BACKUP" && -e "$SYSTEM_GO_BIN_BACKUP" ]]; then mv "$SYSTEM_GO_BIN_BACKUP" /usr/local/bin/go; fi
    if [[ -n "$SYSTEM_GOFMT_BIN_BACKUP" && -e "$SYSTEM_GOFMT_BIN_BACKUP" ]]; then mv "$SYSTEM_GOFMT_BIN_BACKUP" /usr/local/bin/gofmt; fi

    rm -f "$SYSTEM_GO_MARKER" "$SYSTEM_GO_STATE_FILE"
    log_success "System-wide Go change made by this testenvironment was reverted"
}

cmd_uninstall() {
    log_step "Fully uninstall testenvironment-owned additions"
    stop_runtime
    bash "$SCRIPT_DIR/03-topology.sh" clean 2>/dev/null || true
    restore_system_go_if_owned

    if [[ -f "$APT_MANIFEST" ]]; then
        mapfile -t _pkgs < <(sed '/^[[:space:]]*$/d' "$APT_MANIFEST" | sort -u)
        if ((${#_pkgs[@]} > 0)); then
            log_info "Removing APT packages installed by this testenvironment: ${_pkgs[*]}"
            DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y "${_pkgs[@]}" || true
            DEBIAN_FRONTEND=noninteractive apt-get autoremove -y || true
        fi
    fi

    [[ -f "$SCION_APT_SOURCE_MARKER" ]] && rm -f /etc/apt/sources.list.d/scion-lcschulz.list
    [[ -f "$SCION_APT_KEY_MARKER" ]] && rm -f /usr/share/keyrings/scion-lcschulz.gpg
    rm -rf "$RUNTIME_DIR" "$DEPS_DIR" "$INSTALL_STATE_DIR"

    log_success "Removed runtime, testenvironment-owned cached dependencies and testenvironment-installed APT packages"
    if [[ "$SCION_SOURCE" == "external" ]]; then log_info "External SCION source checkout was not deleted: $SCION_DIR"; fi
    log_info "Pre-existing system Go was not removed; a system Go installed by this testenvironment was reverted"
    log_info "APT packages that existed before the first setup were NOT removed"
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
  sudo ./testenvironment.bash purge     # down + remove .runtime/.deps; keep system packages
  sudo ./testenvironment.bash uninstall # rollback additions owned by this testenvironment

Optional debugging packages:
  sudo INSTALL_DEBUG_TOOLS=1 ./testenvironment.bash

Non-interactive Go selection:
  sudo GO_INSTALL_MODE=managed ./testenvironment.bash
  sudo GO_INSTALL_MODE=system ./testenvironment.bash
  sudo GO_INSTALL_MODE=external GO_BIN=/path/to/go ./testenvironment.bash

Fresh clone workflow:
  git clone <OUR-REPO>
  cd <OUR-REPO>/testenvironment
  chmod +x testenvironment.bash
  sudo ./testenvironment.bash
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
