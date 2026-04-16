#!/usr/bin/env bash
#===============================================================================
# Step 5: Echo Server Setup
# Starts the SCION echo server for return path testing
# Uses pan.ListenUDP for SCION-awareness (like helloworld example)
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

check_root

log_step "Setting up Echo Server"

#-------------------------------------------------------------------------------
# Kill existing echo server
#-------------------------------------------------------------------------------

kill_existing() {
    log_info "Killing existing echo servers..."
    
    sudo pkill -f "scion_echo_server" 2>/dev/null || true
    sleep 1
    
    log_success "Killed existing echo servers"
}

#-------------------------------------------------------------------------------
# Start echo server
#-------------------------------------------------------------------------------

start_echo_server() {
    log_info "Starting SCION echo server on port $SCION_ECHO_PORT..."
    log_info "Echo server uses pan package for SCION-awareness"
    
    # Create log file
    touch "$LOGS_DIR/echo-server.log"
    
    # Bind to SCION address for AS64514
    # This must match the address the client sends to
    local ECHO_BIND_ADDR="fc00:10fc:200::2"
    
    log_info "SCION echo server (pan) binding to: $ECHO_BIND_ADDR:$SCION_ECHO_PORT"
    
    # Check if pan-based echo server exists
    if [ -x "$BIN_DIR/scion_echo_server_pan" ]; then
        log_info "Using pan-based echo server"
        
        # Start in server namespace
        sudo ip netns exec "$SERVER_NS" bash -c "
            cd '$SCRIPT_DIR/..'
            '$BIN_DIR/scion_echo_server_pan' -bind '$ECHO_BIND_ADDR' -port $SCION_ECHO_PORT -v >> '$LOGS_DIR/echo-server.log' 2>&1
        " &
    else
        log_warn "pan-based echo server not found, trying regular one"
        
        # Fall back to regular echo server
        sudo ip netns exec "$SERVER_NS" bash -c "
            cd '$SCRIPT_DIR/..'
            '$BIN_DIR/scion_echo_server' -port $SCION_ECHO_PORT -bind '$ECHO_BIND_ADDR' -v >> '$LOGS_DIR/echo-server.log' 2>&1
        " &
    fi
    
    local echo_pid=$!
    log_debug "Echo server PID: $echo_pid"
    
    # Wait for server to start
    sleep 2
    
    # Check if running
    if pgrep -f "scion_echo_server" &>/dev/null; then
        log_success "Echo server started on SCION address $ECHO_BIND_ADDR:$SCION_ECHO_PORT"
    else
        log_error "Echo server failed to start"
        log_debug "Check logs: tail -f $LOGS_DIR/echo-server.log"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# Verify
#-------------------------------------------------------------------------------

verify_echo() {
    log_info "Verifying echo server..."
    
    if pgrep -f "scion_echo_server" &>/dev/null; then
        log_success "Echo server is running"
    else
        log_error "Echo server not running"
        return 1
    fi
    
    return 0
}

#-------------------------------------------------------------------------------
# Status
#-------------------------------------------------------------------------------

show_status() {
    echo ""
    echo "=== Echo Server Status ==="
    
    pgrep -af "scion_echo_server" || echo "  (not running)"
    
    echo ""
    echo "Logs:"
    echo "  tail -f $LOGS_DIR/echo-server.log"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

cmd_up() {
    kill_existing
    start_echo_server
    verify_echo
    show_status
}

cmd_down() {
    log_info "Stopping echo server..."
    kill_existing
    log_success "Echo server stopped"
}

cmd_status() {
    show_status
}

cmd_logs() {
    echo "=== Echo Server Logs ==="
    tail -50 "$LOGS_DIR/echo-server.log" 2>/dev/null || echo "(no logs)"
}

#-------------------------------------------------------------------------------
# Usage
#-------------------------------------------------------------------------------

usage() {
    cat << EOF
Usage: $0 <command>

Commands:
    up         Start echo server
    down       Stop echo server
    status     Show status
    logs       Show logs

Examples:
    sudo $0 up       # Start echo server
    sudo $0 status   # Show status
    sudo $0 logs     # View logs
    sudo $0 down     # Stop echo server
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
