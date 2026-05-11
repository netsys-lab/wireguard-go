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
    if sudo ip netns exec "$CLIENT_NS" ping -c 3 10.0.0.1; then
        log_success "Basic connectivity: PASS"
        return 0
    else
        log_error "Basic connectivity: FAIL"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# Test 2: SCION ping -sciond from Client
#-------------------------------------------------------------------------------

test_sciond_from_client() {
    log_info "Test 2: Checking scion ping from Client to Server..."

    echo "Deamon addr: "${SERVER_65413_sciond_addr%%/*}""
    echo "Scion dir: "$SCION_DIR"/bin/scion"""
    echo "sudo ip netns exec "$CLIENT_NS" \
        "$SCION_DIR"/bin/scion ping --sciond "${SERVER_65413_sciond_addr%%/*}":30255 1-64514,127.0.0.1"
     if output=$(sudo ip netns exec "$CLIENT_NS" \
        "$SCION_DIR"/bin/scion ping --sciond "${SERVER_65413_sciond_addr%%/*}":30255 1-64514,127.0.0.1 -c 3 2>&1); then

        log_success "SCION ping command executed"
        echo "$output"

    else
        log_warn "SCION ping command not executed"
        echo "$output"
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
    echo ""
    echo "  # Manual ping test"
    echo "  sudo ip netns exec $CLIENT_NS ping -c 3 10.0.0.1"
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
    test_sciond_from_client || ((failed++))
    
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
