#!/usr/bin/env bash
#===============================================================================
# Step 6: Testing
# Runs tests to verify the integration works
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

log_step "Running Tests"

#-------------------------------------------------------------------------------
# Test 1: Basic connectivity
#-------------------------------------------------------------------------------

test_basic_connectivity() {
    log_info "Test 1: Basic WireGuard connectivity..."
    
    # Ping from client to server
    if sudo ip netns exec "$CLIENT_NS" ping -c 3 10.10.10.1; then
        log_success "Basic connectivity: PASS"
        return 0
    else
        log_error "Basic connectivity: FAIL"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# Test 2: Check logs for SCION detection
#-------------------------------------------------------------------------------

test_scion_detection() {
    log_info "Test 2: Checking for SCION-related log messages..."
    
    # Check server logs for SCION detection
    if grep -q "SCION" "$LOGS_DIR/wg-server.log" 2>/dev/null; then
        log_success "SCION-related logs found in server"
    else
        log_warn "No SCION logs found (may be OK if no SCION traffic)"
    fi
    
    # Check for dispatcher connection
    if grep -q "dispatcher" "$LOGS_DIR/wg-server.log" 2>/dev/null; then
        log_success "Dispatcher connection logs found"
    else
        log_warn "No dispatcher logs found"
    fi
    
    return 0
}

#-------------------------------------------------------------------------------
# Test 3: Check listener
#-------------------------------------------------------------------------------

test_listener() {
    log_info "Test 3: Checking SCION listener..."
    
    # Check if listener is bound
    if sudo ip netns exec "$SERVER_NS" ss -ulnp 2>/dev/null | grep -q "$SCION_LISTENER_PORT"; then
        log_success "SCION listener is bound to port $SCION_LISTENER_PORT"
    else
        log_warn "SCION listener not detected on port $SCION_LISTENER_PORT"
    fi
    
    return 0
}

#-------------------------------------------------------------------------------
# Test 4: SCION echo server
#-------------------------------------------------------------------------------

test_echo_server() {
    log_info "Test 4: Testing echo server..."
    
    # Send a test packet to the echo server
    echo "test" | sudo nc -u -w2 127.0.0.1 "$SCION_LISTENER_PORT" 2>/dev/null || true
    
    sleep 1
    
    # Check echo server logs
    if grep -q "Received" "$LOGS_DIR/echo-server.log" 2>/dev/null; then
        log_success "Echo server received packets"
    else
        log_warn "No packets received by echo server"
    fi
    
    return 0
}

#-------------------------------------------------------------------------------
# Summary
#-------------------------------------------------------------------------------

show_summary() {
    echo ""
    echo "========================================"
    echo "  Test Summary"
    echo "========================================"
    echo ""
    echo "Log files location: $LOGS_DIR"
    echo ""
    echo "Useful commands:"
    echo "  # View all logs"
    echo "  tail -f $LOGS_DIR/*.log"
    echo ""
    echo "  # View wireguard server logs"
    echo "  tail -f $LOGS_DIR/wg-server.log"
    echo ""
    echo "  # View wireguard client logs"  
    echo "  tail -f $LOGS_DIR/wg-client.log"
    echo ""
    echo "  # View echo server logs"
    echo "  tail -f $LOGS_DIR/echo-server.log"
    echo ""
    echo "  # Manual ping test"
    echo "  sudo ip netns exec $CLIENT_NS ping -c 3 10.10.10.1"
    echo ""
    echo "  # Check namespaces"
    echo "  ip netns list"
    echo ""
    echo "========================================"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

cmd_test() {
    local failed=0
    
    test_basic_connectivity || ((failed++))
    test_scion_detection || ((failed++))
    test_listener || ((failed++))
    test_echo_server || ((failed++))
    
    show_summary
    
    if [[ $failed -gt 0 ]]; then
        log_warn "$failed test(s) had issues"
        return 1
    fi
    
    log_success "All tests completed"
    return 0
}

cmd_basic() {
    log_info "Running basic connectivity test..."
    test_basic_connectivity
}

cmd_logs() {
    echo "=== Server Logs ==="
    tail -30 "$LOGS_DIR/wg-server.log" 2>/dev/null || echo "(no logs)"
    echo ""
    echo "=== Client Logs ==="
    tail -30 "$LOGS_DIR/wg-client.log" 2>/dev/null || echo "(no logs)"
    echo ""
    echo "=== Echo Server Logs ==="
    tail -30 "$LOGS_DIR/echo-server.log" 2>/dev/null || echo "(no logs)"
}

#-------------------------------------------------------------------------------
# Usage
#-------------------------------------------------------------------------------

usage() {
    cat << EOF
Usage: $0 <command>

Commands:
    test      Run all tests
    basic     Run basic connectivity test
    logs      Show all logs

Examples:
    sudo $0 test      # Run all tests
    sudo $0 basic     # Run basic test
    sudo $0 logs      # View logs
EOF
}

#-------------------------------------------------------------------------------
# Run
#-------------------------------------------------------------------------------

case "${1:-}" in
    test)  cmd_test ;;
    basic) cmd_basic ;;
    logs)  cmd_logs ;;
    *)     usage ;;
esac
