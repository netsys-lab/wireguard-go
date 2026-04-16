#!/usr/bin/env bash
#===============================================================================
# Step 1: Validate SCION Packet in Topology
# 
# This script validates that our generated SCION packet is valid and can be
# sent through the SCION topology.
#
# Steps:
# 1. Check if SCION topology is running
# 2. Parse SCION packet with scapy-scion-int
# 3. Send packet to Border Router
# 4. Capture at BR to verify receipt
#
# Usage:
#   sudo ./01-validate-scion-packet.sh
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TESTENV_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PACKETS_DIR="$TESTENV_DIR/packets"
SCION_DIR="/home/paul/Scintra/scion"
SCAPY_DIR="/home/paul/Scintra/scapy-scion-int"

# Source config
source "$TESTENV_DIR/config.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

usage() {
    cat << EOF
Usage: $0 [command]

Commands:
  check     - Just parse and validate the packet (no network)
  send      - Send packet to BR and capture
  help      - Show this help

Examples:
  sudo $0 check    # Validate packet structure only
  sudo $0 send     # Send packet through topology
EOF
}

#-------------------------------------------------------------------------------
# Step 1a: Parse and validate packet with scapy-scion-int
#-------------------------------------------------------------------------------

do_check() {
    log_info "Step 1a: Validating SCION packet with scapy-scion-int"
    
    local scion_pkt="$PACKETS_DIR/scion/scion_client_to_server.bin"
    
    if [[ ! -f "$scion_pkt" ]]; then
        log_error "SCION packet not found: $scion_pkt"
        log_info "Run: python3 $PACKETS_DIR/create_scion_packets.py"
        exit 1
    fi
    
    log_info "Parsing SCION packet: $scion_pkt"
    
    # Run scapy to parse the packet
    ip netns exec Server bash -c "
        source $SCAPY_DIR/.venv/bin/activate
        cd $SCAPY_DIR
        python3 -c \"
from scapy.all import *
from scapy_scion.layers.scion import SCION, SCIONPath

# Load packet
with open('$scion_pkt', 'rb') as f:
    pkt_bytes = f.read()

print(f'Packet size: {len(pkt_bytes)} bytes')
print(f'First 64 bytes: {pkt_bytes[:64].hex()}')
print()

pkt = Packet(pkt_bytes)
print('=== Packet Layers ===')
pkt.show()
print()

if SCION in pkt:
    scion = pkt[SCION]
    print('=== SCION Header ===')
    print(f'Source IA: {scion.src_isd}-{scion.src_asn}')
    print(f'Dest IA:   {scion.dst_isd}-{scion.dst_asn}')
    print(f'Source Host: {scion.src_host}')
    print(f'Dest Host:   {scion.dst_host}')
    print()
    print('SUCCESS: Packet is valid SCION!')
else:
    print('ERROR: No SCION layer found!')
    exit(1)
\"
    "
    
    log_ok "Packet validation complete"
}

#-------------------------------------------------------------------------------
# Step 1b: Send packet to Border Router and capture
#-------------------------------------------------------------------------------

do_send() {
    log_info "Step 1b: Sending SCION packet to Border Router"
    
    # Check if SCION is running
    if ! ip netns exec Server pgrep -x scion &>/dev/null; then
        log_warn "SCION is not running in Server namespace"
        log_info "Start it with: ip netns exec Server $SCION_DIR/bin/scion run &"
        log_info "Or run: sudo $TESTENV_DIR/testenv.sh scion"
    fi
    
    local scion_pkt="$PACKETS_DIR/scion/scion_client_to_server.bin"
    
    # Start tcpdump capture in background
    log_info "Starting packet capture on BR port 31006..."
    ip netns exec Server tcpdump -i lo -nn port 31006 -c 3 -w /tmp/br_capture.pcap &
    local tcpdump_pid=$!
    sleep 1
    
    # Send the packet
    log_info "Sending SCION packet to BR (127.0.0.25:31006)..."
    ip netns exec Server bash -c "
        source $SCAPY_DIR/.venv/bin/activate
        python3 -c \"
from scapy.all import *
from scapy_scion.layers.scion import SCION

with open('$scion_pkt', 'rb') as f:
    pkt_bytes = f.read()

# Send the packet - the file contains IPv4/UDP/SCRYPT underlay already
send(Raw(pkt_bytes))
print('Packet sent!')
\"
    "
    
    # Wait for capture
    sleep 2
    
    # Kill tcpdump
    kill $tcpdump_pid 2>/dev/null || true
    
    # Show capture
    log_info "Capture results:"
    ip netns exec Server tcpdump -r /tmp/br_capture.pcap -nn 2>/dev/null || log_warn "No packets captured"
    
    log_ok "Send test complete"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

main() {
    check_root
    
    local cmd="${1:-check}"
    
    echo ""
    echo "========================================"
    echo "  Step 1: Validate SCION Packet"
    echo "========================================"
    echo ""
    
    case $cmd in
        check)
            do_check
            ;;
        send)
            do_send
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: $cmd"
            usage
            exit 1
            ;;
    esac
}

main "$@"
