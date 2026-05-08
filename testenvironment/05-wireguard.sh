#!/usr/bin/env bash
#===============================================================================
# Step 4: WireGuard Setup
# Starts wireguard-go in both namespaces and configures peers
# 
# NOTE: Server wireguard-go runs WITHOUT SCION_CONFIG_DIR (vanilla WireGuard)
#       Client wireguard-go runs WITH SCION_CONFIG_DIR (SCION translation enabled)
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

check_root

log_step "Setting up WireGuard"

#-------------------------------------------------------------------------------
# Load keys
#-------------------------------------------------------------------------------

load_keys() {
    log_info "Loading WireGuard keys..."
    
    if [[ ! -f "$KEYS_DIR/server_private" ]]; then
        log_error "Server keys not found. Run 02-build.sh first"
        return 1
    fi
    
    if [[ ! -f "$KEYS_DIR/client_private" ]]; then
        log_error "Client keys not found. Run 02-build.sh first"
        return 1
    fi
    
    # UAPI requires keys in HEX format, not base64
    export SERVER_PRIVATE_HEX=$(base64 -d "$KEYS_DIR/server_private" | xxd -p -c 256)
    export SERVER_PUBLIC_HEX=$(base64 -d "$KEYS_DIR/server_public" | xxd -p -c 256)
    export CLIENT_PRIVATE_HEX=$(base64 -d "$KEYS_DIR/client_private" | xxd -p -c 256)
    export CLIENT_PUBLIC_HEX=$(base64 -d "$KEYS_DIR/client_public" | xxd -p -c 256)
    
    log_success "Keys loaded (converted to HEX for UAPI)"
    log_debug "Server Public: $SERVER_PUBLIC_HEX"
    log_debug "Client Public: $CLIENT_PUBLIC_HEX"
}

#-------------------------------------------------------------------------------
# Kill existing wireguard-go
#-------------------------------------------------------------------------------

kill_existing() {
    log_info "Killing existing wireguard-go processes..."
    
    sudo pkill -f "wireguard-go.*$WG_SERVER_IFACE" 2>/dev/null || true
    sudo pkill -f "wireguard-go.*$WG_CLIENT_IFACE" 2>/dev/null || true
    sudo rm -f /var/run/wireguard/$WG_SERVER_IFACE.sock 2>/dev/null || true
    sudo rm -f /var/run/wireguard/$WG_CLIENT_IFACE.sock 2>/dev/null || true
    sleep 1
    
    log_success "Killed existing processes"
}

#-------------------------------------------------------------------------------
# Start server-side wireguard-go (VANILLA - NO SCION)
#-------------------------------------------------------------------------------

start_server_wg() {
    # log_info "Starting VANILLA wireguard-go in $SERVER_NS namespace..."
    
    # Create log file
    touch "$LOGS_DIR/wg-server.log"
    
    # Start wireguard-go in server namespace - VANILLA (NO SCION)
    # Server should be vanilla WireGuard - no translation
    # Just receives packets and writes to TUN (kernel handles routing to BR)
    sudo ip netns exec "$SERVER_NS" bash -c "
        export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
        export LOG_LEVEL='$LOG_LEVEL'
        # NO SCION_CONFIG_DIR - vanilla WireGuard
        # Server just handles regular WG traffic
        
        cd '$SCRIPT_DIR/..'
        '$BIN_DIR/wireguard-go' --foreground '$WG_SERVER_IFACE' >> '$LOGS_DIR/wg-server.log' 2>&1
    " &
    
    local server_pid=$!
    log_debug "Server wireguard-go PID: $server_pid"
    
    # Wait for interface to appear
    sleep 3
    
    # Check if running
    if sudo ip netns exec "$SERVER_NS" ip link show "$WG_SERVER_IFACE" 2>/dev/null; then
        log_success "Server wireguard-go started (VANILLA)"
    else
        log_error "Server wireguard-go failed to start"
        log_debug "Check logs: tail -f $LOGS_DIR/wg-server.log"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# Configure server interface
#-------------------------------------------------------------------------------

configure_server_iface() {
    log_info "Configuring server WireGuard interface..."
    
    local SERVER_IP="${WG_SERVER_IP%/*}"
    
    # Configure using wireguard-go UAPI socket (must run inside namespace)
    wait_for_socket() {
        for i in {1..30}; do
            [[ -S "/var/run/wireguard/$WG_SERVER_IFACE.sock" ]] && return 0
            sleep 0.2
        done
        return 1
    }
    
    wait_for_socket || { log_error "Server UAPI socket not found"; return 1; }
    
    # Set server private key and peer (run inside namespace, using HEX keys)
    sudo ip netns exec "$SERVER_NS" bash -c "
        export SERVER_PRIVATE_HEX='$SERVER_PRIVATE_HEX'
        export CLIENT_PUBLIC_HEX='$CLIENT_PUBLIC_HEX'
        echo \"set=1
private_key=\$SERVER_PRIVATE_HEX
listen_port=51820\" | socat - UNIX-CONNECT:/var/run/wireguard/$WG_SERVER_IFACE.sock
    " || true

    sudo ip netns exec "$SERVER_NS" bash -c "
        export CLIENT_PUBLIC_HEX='$CLIENT_PUBLIC_HEX'
        echo \"set=1
public_key=\$CLIENT_PUBLIC_HEX
allowed_ip=10.0.0.0/8
allowed_ip=10.10.10.2/32
allowed_ip=fd00::2/128
persistent_keepalive_interval=25\" | socat - UNIX-CONNECT:/var/run/wireguard/$WG_SERVER_IFACE.sock
    " || true
    
    # Set IP address
    sudo ip netns exec "$SERVER_NS" ip addr add "$WG_SERVER_IP" dev "$WG_SERVER_IFACE"
    sudo ip netns exec "$SERVER_NS" ip -6 addr add "$WG_SERVER_IP_V6" dev "$WG_SERVER_IFACE"
    
    # Assign SCION-mapped addresses to wg-server (must match BR internal_addr in topology.json)
    # AS64513 BR: 127.0.0.25:31006, AS64514 BR: 127.0.0.33:31010
    # IPv4 matches BR interfaces so kernel routes to BR automatically
    sudo ip netns exec "$SERVER_NS" ip addr add 127.0.0.25/32 dev "$WG_SERVER_IFACE"
    sudo ip netns exec "$SERVER_NS" ip addr add 127.0.0.33/32 dev "$WG_SERVER_IFACE"
    
    # SCION addresses on wg-server - kernel routes locally
    # NOTE: For SCION to work, BR must also have these addresses
    sudo ip netns exec "$SERVER_NS" ip -6 addr add fc00:10fc:100::/64 dev "$WG_SERVER_IFACE"
    sudo ip netns exec "$SERVER_NS" ip -6 addr add fc00:10fc:100::1/64 dev "$WG_SERVER_IFACE"
    sudo ip netns exec "$SERVER_NS" ip -6 addr add fc00:10fc:200::/64 dev "$WG_SERVER_IFACE"
    sudo ip netns exec "$SERVER_NS" ip -6 addr add fc00:10fc:200::1/64 dev "$WG_SERVER_IFACE"
    sudo ip netns exec "$SERVER_NS" ip -6 addr add fc00:10fc:200::2/64 dev "$WG_SERVER_IFACE"
    
    sudo ip netns exec "$SERVER_NS" ip link set "$WG_SERVER_IFACE" up
    
    # Enable IP forwarding
    sudo ip netns exec "$SERVER_NS" sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

    # Add explicit routes to BR (via lo, since BR listens on 127.0.0.25:30442)
    # This ensures packets TO 127.0.0.25 go to the BR, not stay local
    sudo ip netns exec "$SERVER_NS" ip route add 127.0.0.25/32 dev lo || true
    
    log_success "Server interface configured"
}

#-------------------------------------------------------------------------------
# Start client-side wireguard-go (WITH SCION TRANSLATION)
#-------------------------------------------------------------------------------

start_client_wg() {
    log_info "Starting SCION-aware wireguard-go in $CLIENT_NS namespace..."
    
    # Create log file
    touch "$LOGS_DIR/wg-client.log"
    
    # Start wireguard-go in client namespace - WITH SCION CONFIG
    # Client translates IP <-> SCION
    sudo ip netns exec "$CLIENT_NS" bash -c "
        export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
        export LOG_LEVEL='$LOG_LEVEL'
        export SCION_CONFIG_DIR='$SCION_CONFIG_DIR'
        export SCION_LOCAL_IA='$SCION_LOCAL_IA'
        export SCION_UNDERLAY_PORT='$SCION_UNDERLAY_PORT'
        
        cd '$SCRIPT_DIR/../'
        '$BIN_DIR/wireguard-go' --foreground '$WG_CLIENT_IFACE' >> '$LOGS_DIR/wg-client.log' 2>&1
    " &
    
    local client_pid=$!
    log_debug "Client wireguard-go PID: $client_pid"
    
    # Wait for interface to appear
    sleep 3
    
    # Check if running
    if sudo ip netns exec "$CLIENT_NS" ip link show "$WG_CLIENT_IFACE" 2>/dev/null; then
        log_success "Client wireguard-go started (SCION-aware)"
    else
        log_error "Client wireguard-go failed to start"
        log_debug "Check logs: tail -f $LOGS_DIR/wg-client.log"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# Configure client interface
#-------------------------------------------------------------------------------

configure_client_iface() {
    log_info "Configuring client WireGuard interface..."
    
    # Wait for socket
    wait_for_socket() {
        for i in {1..30}; do
            [[ -S "/var/run/wireguard/$WG_CLIENT_IFACE.sock" ]] && return 0
            sleep 0.2
        done
        return 1
    }
    
    wait_for_socket || { log_error "Client UAPI socket not found"; return 1; }
    
    # Set client private key and peer (run inside namespace, using HEX keys)
    sudo ip netns exec "$CLIENT_NS" bash -c "
        export CLIENT_PRIVATE_HEX='$CLIENT_PRIVATE_HEX'
        echo \"set=1
private_key=\$CLIENT_PRIVATE_HEX
listen_port=51820\" | socat - UNIX-CONNECT:/var/run/wireguard/$WG_CLIENT_IFACE.sock
    " || true

    sudo ip netns exec "$CLIENT_NS" bash -c "
        export SERVER_PUBLIC_HEX='$SERVER_PUBLIC_HEX'
        echo \"set=1
public_key=\$SERVER_PUBLIC_HEX
allowed_ip=0.0.0.0/0
allowed_ip=::/0
endpoint=$WG_ENDPOINT
persistent_keepalive_interval=25\" | socat - UNIX-CONNECT:/var/run/wireguard/$WG_CLIENT_IFACE.sock
    " || true
    
    # Set IP address
    sudo ip netns exec "$CLIENT_NS" ip addr add "$WG_CLIENT_IP" dev "$WG_CLIENT_IFACE"
    sudo ip netns exec "$CLIENT_NS" ip -6 addr add "$WG_CLIENT_IP_V6" dev "$WG_CLIENT_IFACE"
    sudo ip netns exec "$CLIENT_NS" ip link set "$WG_CLIENT_IFACE" up
    
    log_success "Client interface configured"
}

#-------------------------------------------------------------------------------
# Add routes
#-------------------------------------------------------------------------------

add_routes() {
    log_info "Adding routes..."
    
    # Client route to server (IPv4)
    sudo ip netns exec "$CLIENT_NS" ip route add 10.10.10.1/32 dev "$WG_CLIENT_IFACE" 2>/dev/null || true
    
    # Client route to server (IPv6)
    sudo ip netns exec "$CLIENT_NS" ip -6 route add fd00::1/128 dev "$WG_CLIENT_IFACE" 2>/dev/null || true
    
    # SCION-mapped routes (fc00::/8) - route through tunnel
    sudo ip netns exec "$CLIENT_NS" ip -6 route add fc00::/8 dev "$WG_CLIENT_IFACE" 2>/dev/null || true
    
    log_success "Routes added"
}

#-------------------------------------------------------------------------------
# Verify WireGuard
#-------------------------------------------------------------------------------

verify_wg() {
    log_info "Verifying WireGuard setup..."
    
    local failed=0
    
    # Check server interface
    if sudo ip netns exec "$SERVER_NS" ip link show "$WG_SERVER_IFACE" &>/dev/null; then
        log_success "Server interface exists"
    else
        log_error "Server interface not found"
        ((failed++))
    fi
    
    # Check client interface
    if sudo ip netns exec "$CLIENT_NS" ip link show "$WG_CLIENT_IFACE" &>/dev/null; then
        log_success "Client interface exists"
    else
        log_error "Client interface not found"
        ((failed++))
    fi
    
    # Check pids
    local server_pid=$(pgrep -f "wireguard-go.*$WG_SERVER_IFACE" 2>/dev/null || echo "")
    local client_pid=$(pgrep -f "wireguard-go.*$WG_CLIENT_IFACE" 2>/dev/null || echo "")
    
    if [[ -n "$server_pid" ]]; then
        log_success "Server process running (PID: $server_pid)"
    else
        log_error "Server process not running"
        ((failed++))
    fi
    
    if [[ -n "$client_pid" ]]; then
        log_success "Client process running (PID: $client_pid)"
    else
        log_error "Client process not running"
        ((failed++))
    fi
    
    if [[ $failed -gt 0 ]]; then
        return 1
    fi
    
    return 0
}

#-------------------------------------------------------------------------------
# Status
#-------------------------------------------------------------------------------

show_status() {
    echo ""
    echo "=== WireGuard Status ==="
    
    echo "Server namespace:"
    sudo ip netns exec "$SERVER_NS" wg show "$WG_SERVER_IFACE" 2>/dev/null || echo "  (not configured)"
    
    echo ""
    echo "Client namespace:"
    sudo ip netns exec "$CLIENT_NS" wg show "$WG_CLIENT_IFACE" 2>/dev/null || echo "  (not configured)"
    
    echo ""
    echo "Processes:"
    pgrep -af "wireguard-go.*($WG_SERVER_IFACE|$WG_CLIENT_IFACE)" || echo "  (none)"
    
    echo ""
    echo "Logs:"
    echo "  Server: tail -f $LOGS_DIR/wg-server.log"
    echo "  Client: tail -f $LOGS_DIR/wg-client.log"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

cmd_up() {
    load_keys
    kill_existing
    start_server_wg
    configure_server_iface
    start_client_wg
    configure_client_iface
    add_routes
    verify_wg
    show_status
}

cmd_down() {
    log_info "Stopping WireGuard..."
    kill_existing
    log_success "WireGuard stopped"
}

cmd_status() {
    show_status
}

cmd_logs() {
    echo "=== Server Logs ==="
    tail -50 "$LOGS_DIR/wg-server.log" 2>/dev/null || echo "(no logs)"
    echo ""
    echo "=== Client Logs ==="
    tail -50 "$LOGS_DIR/wg-client.log" 2>/dev/null || echo "(no logs)"
}

#-------------------------------------------------------------------------------
# Usage
#-------------------------------------------------------------------------------

usage() {
    cat << EOF
Usage: $0 <command>

Commands:
    up         Setup and start WireGuard
    down       Stop WireGuard
    status     Show WireGuard status
    logs       Show WireGuard logs

Note:
    - Server wireguard-go runs VANILLA (no SCION config)
    - Client wireguard-go runs SCION-aware (with SCION config)

Examples:
    sudo $0 up       # Setup and start WireGuard
    sudo $0 status   # Show status
    sudo $0 logs     # View logs
    sudo $0 down     # Stop WireGuard
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
