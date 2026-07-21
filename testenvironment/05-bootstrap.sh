#!/usr/bin/env bash
#===============================================================================
# Step 4: Bootstrap Server
# Starts the SCION bootstrap server (needs generated topology)
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

check_root

log_step "Starting Bootstrap Server"

# Bootstrap configuration
export BOOTSTRAP_AS="${BOOTSTRAP_AS:-AS64512}"
export BOOTSTRAP_BIND="${BOOTSTRAP_BIND:-10.0.0.1}"
export BOOTSTRAP_PORT="${BOOTSTRAP_PORT:-8042}"
export BOOTSTRAP_PY="${BOOTSTRAP_PY:-bootstrap-server.py}"
export ASDIR="$SCION_DIR/gen/$BOOTSTRAP_AS"

#-------------------------------------------------------------------------------
# Check prerequisites
#-------------------------------------------------------------------------------

check_prereqs() {
    log_info "Checking prerequisites..."
    
    # Check topology exists
    if [[ ! -d "$ASDIR" ]]; then
        log_error "SCION topology not found. Run 03a-topology.sh first"
        return 1
    fi
    
    # Check bootstrap server script exists
    if [[ ! -f "$SCRIPT_DIR/../$BOOTSTRAP_PY" ]]; then
        log_error "Bootstrap server script not found: $BOOTSTRAP_PY"
        return 1
    fi
    
    # Check namespace is running
    if ! is_namespace_running "$SERVER_NS"; then
        log_error "Server namespace not running. Run 01-namespaces.sh first"
        return 1
    fi
    
    log_success "Prerequisites met"
    return 0
}

#-------------------------------------------------------------------------------
# Start bootstrap server
#-------------------------------------------------------------------------------

start_bootstrap() {
    log_info "Starting bootstrap server..."
    log_info "  AS: $BOOTSTRAP_AS"
    log_info "  Bind: $BOOTSTRAP_BIND:$BOOTSTRAP_PORT"
    log_info "  ASDIR: $ASDIR"
    
    # Kill existing
    sudo ip netns exec "$SERVER_NS" pkill -f "$BOOTSTRAP_PY" 2>/dev/null || true
    sleep 1
    
    # Start bootstrap server in Server namespace
    sudo ip netns exec "$SERVER_NS" bash -c "
        cd '$SCRIPT_DIR/../'
        nohup python3 '$BOOTSTRAP_PY' '$ASDIR' '$BOOTSTRAP_BIND' '$BOOTSTRAP_PORT' > '$LOGS_DIR/bootstrap.log' 2>&1 &
        echo \$! > /tmp/bootstrap.pid
    "
    
    # Wait for it to start
    sleep 2
    
    # Check if running
    if sudo ip netns exec "$SERVER_NS" ss -lntp 2>/dev/null | grep -q ":$BOOTSTRAP_PORT"; then
        log_success "Bootstrap server started on $BOOTSTRAP_BIND:$BOOTSTRAP_PORT"
    else
        log_error "Bootstrap server failed to start"
        log_debug "Check logs: tail -f $LOGS_DIR/bootstrap.log"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# Stop bootstrap server
#-------------------------------------------------------------------------------

stop_bootstrap() {
    log_info "Stopping bootstrap server..."
    
    sudo ip netns exec "$SERVER_NS" pkill -f "$BOOTSTRAP_PY" 2>/dev/null || true
    rm -f /tmp/bootstrap.pid
    
    log_success "Bootstrap server stopped"
}

#-------------------------------------------------------------------------------
# Verify
#-------------------------------------------------------------------------------

verify_bootstrap() {
    log_info "Verifying bootstrap server..."
    
    if sudo ip netns exec "$SERVER_NS" ss -lntp 2>/dev/null | grep -q ":$BOOTSTRAP_PORT"; then
        log_success "Bootstrap server is running"
        sudo ip netns exec "$SERVER_NS" ss -lntp | grep "$BOOTSTRAP_PORT"
        return 0
    else
        log_error "Bootstrap server not running"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# Status
#-------------------------------------------------------------------------------

show_status() {
    echo ""
    echo "=== Bootstrap Server Status ==="
    
    if sudo ip netns exec "$SERVER_NS" ss -lntp 2>/dev/null | grep -q ":$BOOTSTRAP_PORT"; then
        echo "Bootstrap server: RUNNING"
        sudo ip netns exec "$SERVER_NS" ss -lntp | grep "$BOOTSTRAP_PORT" || true
    else
        echo "Bootstrap server: NOT RUNNING"
    fi
    
    echo ""
    echo "Logs:"
    tail -20 "$LOGS_DIR/bootstrap.log" 2>/dev/null || echo "  (no logs)"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

cmd_up() {
    check_prereqs || return 1
    start_bootstrap
    verify_bootstrap
    show_status
}

cmd_down() {
    stop_bootstrap
}

cmd_status() {
    show_status
}

cmd_logs() {
    echo "=== Bootstrap Logs ==="
    tail -50 "$LOGS_DIR/bootstrap.log" 2>/dev/null || echo "(no logs)"
}

#-------------------------------------------------------------------------------
# Usage
#-------------------------------------------------------------------------------

usage() {
    cat << EOF
Usage: $0 <command>

Commands:
    up         Start bootstrap server
    down       Stop bootstrap server
    status     Show status
    logs       Show logs

Examples:
    sudo $0 up       # Start bootstrap
    sudo $0 status   # Show status
    sudo $0 down     # Stop bootstrap
EOF
}

#-------------------------------------------------------------------------------
# Run
#-------------------------------------------------------------------------------

case "${1:-}" in
    up)    cmd_up ;;
    down)  cmd_down ;;
    status) cmd_status ;;
    logs)  cmd_logs ;;
    *)     usage ;;
esac
