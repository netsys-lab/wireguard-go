#!/usr/bin/env bash
#===============================================================================
# Step 1: Namespace Setup
# Creates network namespaces for Server and Client
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

check_root

log_step "Setting up Network Namespaces"

#-------------------------------------------------------------------------------
# Cleanup existing namespaces
#-------------------------------------------------------------------------------

cleanup_namespaces() {
    log_info "Cleaning up existing namespaces..."
    
    # Kill processes in namespaces first
    for ns in "$SERVER_NS" "$CLIENT_NS"; do
        if is_namespace_running "$ns"; then
            sudo ip netns exec "$ns" pkill -9 wireguard-go 2>/dev/null || true
            sudo ip netns exec "$ns" pkill -9 scion 2>/dev/null || true
        fi
    done
    
    # Delete namespaces
    sudo ip netns del "$SERVER_NS" 2>/dev/null || true
    sudo ip netns del "$CLIENT_NS" 2>/dev/null || true
    
    # Delete any leftover veth pairs
    ip link del veth-server 2>/dev/null || true
    ip link del veth-client 2>/dev/null || true
    
    log_success "Cleanup complete"
}

#-------------------------------------------------------------------------------
# Create namespaces
#-------------------------------------------------------------------------------

create_namespaces() {
    log_info "Creating namespaces: $SERVER_NS, $CLIENT_NS"
    
    sudo ip netns add "$SERVER_NS"
    log_success "Created namespace: $SERVER_NS"
    
    sudo ip netns add "$CLIENT_NS"
    log_success "Created namespace: $CLIENT_NS"
}

#-------------------------------------------------------------------------------
# Create veth pairs
#-------------------------------------------------------------------------------

create_veth() {
    log_info "Creating veth pairs..."
    
    # Create veth pair: server <-> client
    sudo ip link add veth-server type veth peer name veth-client
    log_success "Created veth pair"
    
    # Assign to namespaces
    sudo ip link set veth-server netns "$SERVER_NS"
    sudo ip link set veth-client netns "$CLIENT_NS"
    log_success "Assigned veth to namespaces"
}

#-------------------------------------------------------------------------------
# Configure IP addresses
#-------------------------------------------------------------------------------

configure_ips() {
    log_info "Configuring IP addresses..."
    
    # Server namespace
    sudo ip netns exec "$SERVER_NS" ip addr add "$SERVER_VETH_IP" dev veth-server
    sudo ip netns exec "$SERVER_NS" ip link set veth-server up
    sudo ip netns exec "$SERVER_NS" ip link set lo up
    log_success "Server namespace configured"
    
    # Client namespace  
    sudo ip netns exec "$CLIENT_NS" ip addr add "$CLIENT_VETH_IP" dev veth-client
    sudo ip netns exec "$CLIENT_NS" ip link set veth-client up
    sudo ip netns exec "$CLIENT_NS" ip link set lo up
    log_success "Client namespace configured"
}

#-------------------------------------------------------------------------------
# Setup tun device
#-------------------------------------------------------------------------------

setup_tun() {
    log_info "Setting up /dev/net/tun in namespaces..."
    
    for ns in "$SERVER_NS" "$CLIENT_NS"; do
        sudo ip netns exec "$ns" bash -c '
            mkdir -p /dev/net
            [[ -c /dev/net/tun ]] || mknod /dev/net/tun c 10 200
            chmod 666 /dev/net/tun
        '
    done
    
    log_success "/dev/net/tun configured"
}

#-------------------------------------------------------------------------------
# Verify setup
#-------------------------------------------------------------------------------

verify_setup() {
    log_info "Verifying namespace setup..."
    
    local failed=0
    
    # Check namespaces exist
    for ns in "$SERVER_NS" "$CLIENT_NS"; do
        if is_namespace_running "$ns"; then
            log_success "Namespace $ns exists"
        else
            log_error "Namespace $ns not found"
            ((failed++))
        fi
    done
    
    # Check veth interfaces
    if sudo ip netns exec "$SERVER_NS" ip link show veth-server &>/dev/null; then
        log_success "veth-server exists in $SERVER_NS"
    else
        log_error "veth-server not found in $SERVER_NS"
        ((failed++))
    fi
    
    if sudo ip netns exec "$CLIENT_NS" ip link show veth-client &>/dev/null; then
        log_success "veth-client exists in $CLIENT_NS"
    else
        log_error "veth-client not found in $CLIENT_NS"
        ((failed++))
    fi
    
    # Check IP addresses
    if sudo ip netns exec "$SERVER_NS" ip addr show veth-server | grep -q "$SERVER_VETH_IP"; then
        log_success "Server IP configured"
    else
        log_error "Server IP not configured"
        ((failed++))
    fi
    
    if sudo ip netns exec "$CLIENT_NS" ip addr show veth-client | grep -q "$CLIENT_VETH_IP"; then
        log_success "Client IP configured"
    else
        log_error "Client IP not configured"
        ((failed++))
    fi
    
    if [[ $failed -gt 0 ]]; then
        log_error "Namespace setup verification failed"
        return 1
    fi
    
    log_success "All namespace setup verified"
    return 0
}

#-------------------------------------------------------------------------------
# Status
#-------------------------------------------------------------------------------

show_status() {
    echo ""
    echo "=== Namespace Status ==="
    echo "Namespaces:"
    ip netns list || echo "  (none)"
    
    echo ""
    echo "Server namespace interfaces:"
    sudo ip netns exec "$SERVER_NS" ip addr || echo "  (none)"
    
    echo ""
    echo "Client namespace interfaces:"
    sudo ip netns exec "$CLIENT_NS" ip addr || echo "  (none)"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

cmd_up() {
    create_directories
    cleanup_namespaces
    create_namespaces
    create_veth
    configure_ips
    setup_tun
    verify_setup
    show_status
}

cmd_down() {
    log_step "Tearing down namespaces"
    cleanup_namespaces
    log_success "Namespaces cleaned up"
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
    up         Setup namespaces
    down       Cleanup namespaces
    status     Show namespace status

Examples:
    sudo $0 up       # Setup namespaces
    sudo $0 status   # Show status
    sudo $0 down     # Cleanup
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
