#!/usr/bin/env bash
#===============================================================================
# Step 3c: Start SCION Services
# Starts the SCION infrastructure (after WireGuard is running)
# NOTE: SCION needs WireGuard interfaces to be up to bind to
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

check_root

log_step "Starting SCION Services"

#-------------------------------------------------------------------------------
# Check prerequisites
#-------------------------------------------------------------------------------

check_prereqs() {
    log_info "Checking prerequisites..."
    
    # Check topology exists
    if [[ ! -d "$SCION_DIR/gen/AS${SCION_LOCAL_IA}" ]]; then
        log_error "SCION topology not found. Run 03a-topology.sh first"
        return 1
    fi
    
    # Check bootstrap is running (needed for certificate fetching)
    if ! sudo ip netns exec "$SERVER_NS" ss -lntp 2>/dev/null | grep -q ":8042"; then
        log_warn "Bootstrap server not running (may be needed for initial cert fetch)"
    else
        log_success "Bootstrap server is running"
    fi
    
    # Check WireGuard is running (SCION needs this to bind)
    if ! sudo ip netns exec "$SERVER_NS" ip link show "$WG_SERVER_IFACE" 2>/dev/null | grep -q "state UNKNOWN\|state UP"; then
        log_error "WireGuard interface not up. Run 04-wireguard.sh first"
        return 1
    fi
    
    log_success "Prerequisites met"
    return 0
}

#-------------------------------------------------------------------------------
# Start SCION
#-------------------------------------------------------------------------------

start_scion() {
    log_info "Starting SCION infrastructure in $SERVER_NS namespace..."
    log_info "This allows BR to bind to wg-server's SCION addresses"
    log_info "This may take a while..."
    
    cd "$SCION_DIR"
    
    # Run SCION inside Server namespace so BR can see wg-server's interfaces
    # Supervisor socket needs to be in a namespace-accessible location
    export SUPERVISOR_SOCKET_PATH="/tmp/supervisor-$SERVER_NS.sock"
    
    # Run SCION in Server namespace
    # Key: Supervisor and all SCION processes run inside Server namespace
    if sudo ip netns exec "$SERVER_NS" bash -c "
        export SUPERVISOR_SOCKET_PATH='/tmp/supervisor-$SERVER_NS.sock'
        cd '$SCION_DIR'
        timeout 120 ./scion.sh run 2>&1
    " 2>&1 | tee "$LOGS_DIR/scion-start.log"; then
        log_success "SCION infrastructure started"
    else
        log_error "Failed to start SCION"
        log_debug "Check logs: tail -f $LOGS_DIR/scion-start.log"
        cat "$LOGS_DIR/scion-start.log" | tail -30
        return 1
    fi
    
    # Wait for services to initialize
    log_info "Waiting for SCION to initialize..."
    sleep 5
}

#-------------------------------------------------------------------------------
# Stop SCION
#-------------------------------------------------------------------------------

stop_scion() {
    log_info "Stopping SCION infrastructure in $SERVER_NS namespace..."
    
    cd "$SCION_DIR"
    
    export SUPERVISOR_SOCKET_PATH="/tmp/supervisor-$SERVER_NS.sock"
    
    if sudo ip netns exec "$SERVER_NS" bash -c "
        export SUPERVISOR_SOCKET_PATH='/tmp/supervisor-$SERVER_NS.sock'
        cd '$SCION_DIR'
        ./scion.sh stop 2>&1
    " 2>&1; then
        log_success "SCION stopped"
    else
        log_warn "SCION stop returned error (may already be stopped)"
    fi
}

#-------------------------------------------------------------------------------
# Verify SCION
#-------------------------------------------------------------------------------

verify_scion() {
    log_info "Verifying SCION setup..."
    
    cd "$SCION_DIR"
    export SUPERVISOR_SOCKET_PATH="/tmp/supervisor-$SERVER_NS.sock"
    
    # Check supervisor status inside namespace
    if sudo ip netns exec "$SERVER_NS" bash -c "
        export SUPERVISOR_SOCKET_PATH='/tmp/supervisor-$SERVER_NS.sock'
        cd '$SCION_DIR'
        ./tools/supervisor.sh status 2>/dev/null
    " 2>/dev/null | grep -q "RUNNING"; then
        log_success "SCION processes are running"
    else
        log_warn "SCION processes may not be fully running"
    fi
    
    # Show status
    sudo ip netns exec "$SERVER_NS" bash -c "
        export SUPERVISOR_SOCKET_PATH='/tmp/supervisor-$SERVER_NS.sock'
        cd '$SCION_DIR'
        ./tools/supervisor.sh status 2>/dev/null
    " || true
}

#-------------------------------------------------------------------------------
# Status
#-------------------------------------------------------------------------------

show_status() {
    echo ""
    echo "=== SCION Services Status ==="
    
    cd "$SCION_DIR"
    export SUPERVISOR_SOCKET_PATH="/tmp/supervisor-$SERVER_NS.sock"
    
    echo "Supervisor status:"
    sudo ip netns exec "$SERVER_NS" bash -c "
        export SUPERVISOR_SOCKET_PATH='/tmp/supervisor-$SERVER_NS.sock'
        cd '$SCION_DIR'
        ./tools/supervisor.sh status 2>/dev/null
    " || echo "  (not running)"
    
    echo ""
    echo "Recent logs in root namespace:"
    ls -la "$SCION_DIR/logs/" 2>/dev/null | head -10 || echo "  (no logs)"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

cmd_up() {
    check_prereqs || return 1
    start_scion
    verify_scion
    show_status
}

cmd_down() {
    stop_scion
    log_success "SCION services stopped"
}

cmd_status() {
    show_status
}

#-------------------------------------------------------------------------------
# Usage
#-------------------------------------------------------------------------------

usage() {
    cat << EOF
Usage: $0 <command>

Commands:
    up         Start SCION services
    down       Stop SCION services
    status     Show status

Note: SCION needs WireGuard to be running first!

Examples:
    sudo $0 up       # Start SCION
    sudo $0 status   # Show status
    sudo $0 down     # Stop SCION
EOF
}

#-------------------------------------------------------------------------------
# Run
#-------------------------------------------------------------------------------

case "${1:-}" in
    up)    cmd_up ;;
    down)  cmd_down ;;
    status) cmd_status ;;
    *)     usage ;;
esac
