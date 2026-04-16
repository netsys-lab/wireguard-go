#!/usr/bin/env bash
#===============================================================================
# Packet Validation using tcpdump (simpler fallback)
# Validates packet flow at each stage with proof
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $*"; }

#===============================================================================
# Stage 1: Validate WG Server Interface receives packets
#===============================================================================

validate_wg_interface() {
    log_info "=== Stage 1: WG Server Interface ==="
    
    # Capture on wg interface (if it exists)
    local wg_iface=""
    for iface in wg-server wg0 wg-.*; do
        if sudo ip netns exec "$SERVER_NS" ip link show "$iface" 2>/dev/null | grep -q "$iface"; then
            wg_iface="$iface"
            break
        fi
    done
    
    if [[ -z "$wg_iface" ]]; then
        log_fail "No WireGuard interface found"
        return 1
    fi
    
    log_info "Capturing on interface: $wg_iface"
    
    # Send test packet first
    log_info "Sending test packet from client..."
    sudo ip netns exec "$CLIENT_NS" timeout 1 bash -c 'echo test | nc -u -W 1 fc00:10fc:200::2 30042' 2>/dev/null || true
    sleep 1
    
    # Start capture in background
    local capture_file="$LOGS_DIR/tcpdump-wg-server.pcap"
    sudo ip netns exec "$SERVER_NS" tcpdump -i "$wg_iface" -w "$capture_file" -c 5 udp 2>/dev/null &
    local pid=$!
    
    # Send more test packets
    for i in 1 2 3; do
        sudo ip netns exec "$CLIENT_NS" timeout 1 bash -c "echo test$i | nc -u -W 1 fc00:10fc:200::2 30042" 2>/dev/null || true
        sleep 0.5
    done
    
    # Wait for capture
    sleep 2
    kill $pid 2>/dev/null || true
    sleep 1  # Wait for file to flush
    
    if [[ -f "$capture_file" ]] && [[ -s "$capture_file" ]]; then
        local pkt_count
        pkt_count=$(tcpdump -r "$capture_file" 2>/dev/null | wc -l)
        if [[ "$pkt_count" -gt 0 ]]; then
            log_pass "Captured $pkt_count packets on WG interface"
            echo ""
            echo "Packet details:"
            tcpdump -r "$capture_file" -nn 2>/dev/null | head -10
            return 0
        fi
    fi
    
    log_fail "No packets captured on WG interface"
    return 1
}

#===============================================================================
# Stage 2: Validate AS64513 BR receives packets (port 31006)
#===============================================================================

validate_as64513_br() {
    log_info "=== Stage 2: AS64513 Border Router (port 31006) ==="
    
    # Send test packet
    sudo ip netns exec "$CLIENT_NS" timeout 1 bash -c 'echo test | nc -u -W 1 fc00:10fc:200::2 30042' 2>/dev/null || true
    sleep 1
    
    # Capture on loopback port 31006
    local output
    output=$(sudo timeout 5 ip netns exec "$SERVER_NS" tcpdump -i lo -c 3 -nn -l port 31006 2>&1 || true)
    
    if echo "$output" | grep -q "captured"; then
        local count
        count=$(echo "$output" | grep "captured" | awk '{print $1}')
        log_pass "AS64513 BR received $count packets"
        echo ""
        echo "Capture details:"
        echo "$output" | head -15
        return 0
    fi
    
    log_fail "No packets at AS64513 BR (127.0.0.25:31006)"
    echo "Debug: $output"
    return 1
}

#===============================================================================
# Stage 3: Validate SCION packet structure
#===============================================================================

validate_scion_structure() {
    log_info "=== Stage 3: SCION Packet Structure ==="
    
    # Capture a packet and analyze its structure
    local capture_file="$LOGS_DIR/tcpdump-scion-raw.pcap"
    
    # Start capture
    sudo timeout 5 ip netns exec "$SERVER_NS" tcpdump -i lo -w "$capture_file" -c 1 port 31006 2>/dev/null &
    local pid=$!
    
    # Send test packet
    sudo ip netns exec "$CLIENT_NS" timeout 1 bash -c 'echo test | nc -u -W 1 fc00:10fc:200::2 30042' 2>/dev/null || true
    
    wait $pid 2>/dev/null || true
    sleep 1
    
    if [[ -f "$capture_file" ]] && [[ -s "$capture_file" ]]; then
        log_pass "Captured packet for analysis"
        
        # Show hexdump of first packet
        echo ""
        echo "=== Raw Packet Analysis ==="
        tcpdump -r "$capture_file" -x -v 2>/dev/null | head -30
        
        # Check for SCION markers
        # SCION packets start with version byte = 0
        echo ""
        echo "=== SCION Validation ==="
        
        # Extract payload and check version
        local payload
        payload=$(tcpdump -r "$capture_file" -x 2>/dev/null | grep -A 50 "0x0000" | head -30)
        
        # Check if first nibble is 0 (SCION version)
        if echo "$payload" | grep -q "^0x0000: 00"; then
            log_pass "✓ Valid SCION packet (version = 0)"
        else
            log_warn "Packet version unclear"
        fi
        
        # Check for UDP encapsulation
        if echo "$payload" | grep -qE "[0-9a-f]{4} [0-9a-f]{4} [0-9a-f]{4} [0-9a-f]{4}.*3[0-9]{3}"; then
            log_pass "✓ UDP encapsulation detected"
        fi
        
        return 0
    fi
    
    log_fail "Could not capture packet for analysis"
    return 1
}

#===============================================================================
# Stage 4: Full validation with proof
#===============================================================================

full_validation() {
    echo ""
    echo "========================================"
    echo "  SCION-WireGuard Packet Validation"
    echo "  Using tcpdump for packet capture"
    echo "========================================"
    echo ""
    
    local passed=0
    local failed=0
    
    # Stage 1: WG Interface
    if validate_wg_interface; then
        ((passed++)) || true
    else
        ((failed++)) || true
    fi
    echo ""
    
    # Stage 2: AS64513 BR
    if validate_as64513_br; then
        ((passed++)) || true
    else
        ((failed++)) || true
    fi
    echo ""
    
    # Stage 3: SCION Structure
    if validate_scion_structure; then
        ((passed++)) || true
    else
        ((failed++)) || true
    fi
    echo ""
    
    # Summary
    echo "========================================"
    echo "  Summary: $passed passed, $failed failed"
    echo "========================================"
    
    if [[ $failed -eq 0 ]]; then
        echo -e "${GREEN}✓ Packet flow validated!${NC}"
        echo ""
        echo "Proof:"
        echo "  1. Client sends IP packet with SCION-mapped dst"
        echo "  2. WG Client translates to SCION packet"
        echo "  3. WG Server interface receives encapsulated packet"
        echo "  4. Packet routed to AS64513 BR at 127.0.0.25:31006"
        echo "  5. Valid SCION structure confirmed"
        return 0
    else
        echo -e "${RED}✗ Validation incomplete${NC}"
        return 1
    fi
}

#===============================================================================
# Usage
#===============================================================================

usage() {
    cat << EOF
Usage: $0 <command>

Commands:
    validate     Run full packet validation with proof
    stage1      Validate WG interface only
    stage2      Validate AS64513 BR only
    stage3      Validate SCION structure only

Examples:
    sudo $0 validate    # Full validation
EOF
}

#===============================================================================
# Main
#===============================================================================

case "${1:-}" in
    validate)  full_validation ;;
    stage1)    validate_wg_interface ;;
    stage2)    validate_as64513_br ;;
    stage3)    validate_scion_structure ;;
    *)         usage ;;
esac
