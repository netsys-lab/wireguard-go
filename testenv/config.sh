#!/usr/bin/env bash
#===============================================================================
# Test Environment Configuration
# Modular SCION-WireGuard Integration Test Environment
#===============================================================================

set -euo pipefail

# Configuration - these can be overridden via environment
export TESTENV_DIR="${TESTENV_DIR:-/home/paul/Scintra/wireguard-go/testenv}"
export LOG_DIR="${LOG_DIR:-$TESTENV_DIR/logs}"
export SCION_DIR="${SCION_DIR:-/home/paul/Scintra/scion}"
export SCION_TOPOLOGY="${SCION_TOPOLOGY:-topology/tiny-bgp.topo}"

# Network Configuration
export SERVER_NS="${SERVER_NS:-Server}"
export CLIENT_NS="${CLIENT_NS:-Client}"

# Network IPs
export SERVER_VETH_IP="10.0.0.1/24"
export CLIENT_VETH_IP="10.0.0.2/24"

# WireGuard Configuration
export WG_SERVER_IFACE="wg-server"
export WG_CLIENT_IFACE="wg-client"
export WG_SERVER_IP="10.10.10.1/24"
export WG_CLIENT_IP="10.10.10.2/32"
export WG_SERVER_IP_V6="fd00::1/64"
export WG_CLIENT_IP_V6="fd00::2/64"
export WG_ENDPOINT="10.0.0.1:51820"

# SCION Configuration
export SCION_LOCAL_IA="${SCION_LOCAL_IA:-1-64513}"
export SCION_UNDERLAY_PORT="${SCION_UNDERLAY_PORT:-30041}"
export SCION_LISTENER_PORT=$((SCION_UNDERLAY_PORT + 1))

# SCION ports (actual - from topology + 10 offset not used in current version)
# AS64513 BR: 127.0.0.25:30442 (topology says 31006 but router uses 30442)
# AS64514 BR: 127.0.0.33:30442 (topology says 31010 but router uses 30442)
# Note: topology internal_addr shows 31006/31010 but actual router binds to 30442
export SCION_BR_PORT="${SCION_BR_PORT:-30442}"
export SCION_BR64513_IP="${SCION_BR64513_IP:-127.0.0.25}"
export SCION_BR64514_IP="${SCION_BR64514_IP:-127.0.0.33}"
# Echo server uses different port than dispatcher (30041)
export SCION_ECHO_PORT="${SCION_ECHO_PORT:-30042}"
export SCION_CONFIG_DIR="${SCION_DIR}/gen/AS${SCION_LOCAL_IA#*-}"

# SCION-mapped addresses (must match BR internal_addr in topology.json)
# AS64513: fc00:10fc:100::/64 (BR internal_addr: [fc00:10fc:100::]:31006)
# AS64514: fc00:10fc:200::/64 (BR internal_addr: [fc00:10fc:200::]:31010)

# Directories
export KEYS_DIR="$TESTENV_DIR/keys"
export LOGS_DIR="$LOG_DIR"
export BIN_DIR="$TESTENV_DIR/bin"

# Log levels: silent, verbose, debug
export LOG_LEVEL="${LOG_LEVEL:-verbose}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#-------------------------------------------------------------------------------
# Logging Functions
#-------------------------------------------------------------------------------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_debug() {
    if [[ "$LOG_LEVEL" == "debug" ]]; then
        echo -e "${NC}[DEBUG] $*"
    fi
}

log_step() {
    echo ""
    echo -e "${GREEN}====== STEP: $* ======${NC}"
}

#-------------------------------------------------------------------------------
# Utility Functions
#-------------------------------------------------------------------------------

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_command() {
    local cmd="$1"
    if ! command -v "$cmd" &> /dev/null; then
        log_error "Required command not found: $cmd"
        return 1
    fi
    return 0
}

wait_for() {
    local timeout="$1"
    local description="$2"
    local cmd="$3"
    
    log_debug "Waiting for: $description (timeout: ${timeout}s)"
    
    for i in $(seq 1 "$timeout"); do
        if eval "$cmd" &> /dev/null; then
            log_debug "Success after ${i}s"
            return 0
        fi
        sleep 1
    done
    
    log_error "Timeout waiting for: $description"
    return 1
}

create_directories() {
    log_info "Creating directories..."
    mkdir -p "$TESTENV_DIR"
    mkdir -p "$LOGS_DIR"
    mkdir -p "$KEYS_DIR"
    mkdir -p "$BIN_DIR"
    log_success "Directories created"
}

#-------------------------------------------------------------------------------
# Environment Functions
#-------------------------------------------------------------------------------

get_wg_server_pid() {
    pgrep -f "wireguard-go.*$WG_SERVER_IFACE" 2>/dev/null || echo ""
}

get_wg_client_pid() {
    pgrep -f "wireguard-go.*$WG_CLIENT_IFACE" 2>/dev/null || echo ""
}

get_scion_echo_pid() {
    pgrep -f "scion_echo_server" 2>/dev/null || echo ""
}

is_namespace_running() {
    local ns="$1"
    ip netns list 2>/dev/null | grep -q "^$ns"
}

#-------------------------------------------------------------------------------
# Print Configuration
#-------------------------------------------------------------------------------

print_config() {
    echo ""
    echo "========================================"
    echo "  SCION-WireGuard Test Configuration"
    echo "========================================"
    echo ""
    echo "Directories:"
    echo "  TESTENV_DIR:  $TESTENV_DIR"
    echo "  LOG_DIR:      $LOGS_DIR"
    echo "  SCION_DIR:   $SCION_DIR"
    echo ""
    echo "Namespaces:"
    echo "  SERVER_NS:   $SERVER_NS"
    echo "  CLIENT_NS:   $CLIENT_NS"
    echo ""
    echo "Network:"
    echo "  SERVER_VETH: $SERVER_VETH_IP"
    echo "  CLIENT_VETH: $CLIENT_VETH_IP"
    echo ""
    echo "WireGuard:"
    echo "  WG_SERVER_IFACE: $WG_SERVER_IFACE"
    echo "  WG_CLIENT_IFACE: $WG_CLIENT_IFACE"
    echo "  WG_SERVER_IP:    $WG_SERVER_IP"
    echo "  WG_CLIENT_IP:   $WG_CLIENT_IP"
    echo "  WG_ENDPOINT:    $WG_ENDPOINT"
    echo ""
    echo "SCION:"
    echo "  SCION_LOCAL_IA:      $SCION_LOCAL_IA"
    echo "  SCION_UNDERLAY_PORT: $SCION_UNDERLAY_PORT"
    echo "  SCION_LISTENER_PORT: $SCION_LISTENER_PORT"
    echo "  SCION_CONFIG_DIR:    $SCION_CONFIG_DIR"
    echo ""
    echo "Log Level: $LOG_LEVEL"
    echo "========================================"
    echo ""
}
