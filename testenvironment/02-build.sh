#!/usr/bin/env bash
#===============================================================================
# Step 2: Build Components
# Builds wireguard-go and echo server
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

check_root

log_step "Building Components"

#-------------------------------------------------------------------------------
# Build wireguard-go
#-------------------------------------------------------------------------------

build_wireguard_go() {
    log_info "Building wireguard-go..."
    
    cd "$SCRIPT_DIR/.."
    
    if go build -v -o "$BIN_DIR/wireguard-go" 2>&1; then
        log_success "Built wireguard-go: $BIN_DIR/wireguard-go"
    else
        log_error "Failed to build wireguard-go"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# Build SCION echo server (regular)
#-------------------------------------------------------------------------------

build_echo_server() {
    log_info "Building SCION echo server..."
    
    cd "$SCRIPT_DIR/cmd/scion_echo_server"
    
    if go build -v -o "$BIN_DIR/scion_echo_server" . 2>&1; then
        log_success "Built scion_echo_server: $BIN_DIR/scion_echo_server"
    else
        log_error "Failed to build scion_echo_server"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# Build SCION echo server (pan-based, using SCION-aware sockets)
#-------------------------------------------------------------------------------

build_echo_server_pan() {
    log_info "Building SCION echo server (pan-based)..."
    
    cd "$SCRIPT_DIR/cmd/scion_echo_server_pan"
    
    if go build -v -o "$BIN_DIR/scion_echo_server_pan" . 2>&1; then
        log_success "Built scion_echo_server_pan: $BIN_DIR/scion_echo_server_pan"
    else
        log_error "Failed to build scion_echo_server_pan"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# Generate WireGuard keys
#-------------------------------------------------------------------------------

generate_keys() {
    log_info "Generating WireGuard keys..."
    
    # Server keys
    if [[ ! -f "$KEYS_DIR/server_private" ]]; then
        wg genkey | tee "$KEYS_DIR/server_private" | wg pubkey > "$KEYS_DIR/server_public"
        log_success "Generated server keys"
    else
        log_info "Using existing server keys"
    fi
    
    # Client keys
    if [[ ! -f "$KEYS_DIR/client_private" ]]; then
        wg genkey | tee "$KEYS_DIR/client_private" | wg pubkey > "$KEYS_DIR/client_public"
        log_success "Generated client keys"
    else
        log_info "Using existing client keys"
    fi
    
    # Export keys
    export SERVER_PRIVATE=$(cat "$KEYS_DIR/server_private")
    export SERVER_PUBLIC=$(cat "$KEYS_DIR/server_public")
    export CLIENT_PRIVATE=$(cat "$KEYS_DIR/client_private")
    export CLIENT_PUBLIC=$(cat "$KEYS_DIR/client_public")
    
    log_debug "Server Public Key: $SERVER_PUBLIC"
    log_debug "Client Public Key: $CLIENT_PUBLIC"
}

#-------------------------------------------------------------------------------
# Verify builds
#-------------------------------------------------------------------------------

verify_builds() {
    log_info "Verifying builds..."
    
    local failed=0
    
    if [[ -x "$BIN_DIR/wireguard-go" ]]; then
        log_success "wireguard-go is executable"
    else
        log_error "wireguard-go not found or not executable"
        ((failed++))
    fi
    
    if [[ -x "$BIN_DIR/scion_echo_server" ]]; then
        log_success "scion_echo_server is executable"
    else
        log_error "scion_echo_server not found or not executable"
        ((failed++))
    fi
    
    if [[ -x "$BIN_DIR/scion_echo_server_pan" ]]; then
        log_success "scion_echo_server_pan is executable"
    else
        log_warn "scion_echo_server_pan not found or not executable (optional)"
    fi
    
    if [[ -f "$KEYS_DIR/server_private" && -f "$KEYS_DIR/client_private" ]]; then
        log_success "WireGuard keys exist"
    else
        log_error "WireGuard keys missing"
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
    echo "=== Build Status ==="
    echo "Binary directory: $BIN_DIR"
    ls -la "$BIN_DIR" 2>/dev/null || echo "  (empty)"
    echo ""
    echo "Keys directory: $KEYS_DIR"
    ls -la "$KEYS_DIR" 2>/dev/null || echo "  (empty)"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

cmd_build() {
    create_directories
    build_wireguard_go
    build_echo_server
    build_echo_server_pan
    generate_keys
    verify_builds
    show_status
}

cmd_clean() {
    log_info "Cleaning builds..."
    rm -f "$BIN_DIR/wireguard-go"
    rm -f "$BIN_DIR/scion_echo_server"
    rm -f "$BIN_DIR/scion_echo_server_pan"
    rm -f "$KEYS_DIR"/server_*
    rm -f "$KEYS_DIR"/client_*
    log_success "Builds cleaned"
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
    build    Build components
    clean    Clean builds
    status   Show build status

Examples:
    sudo $0 build   # Build all components
    sudo $0 status   # Show build status
EOF
}

#-------------------------------------------------------------------------------
# Run
#-------------------------------------------------------------------------------

case "${1:-}" in
    build)  cmd_build ;;
    clean)  cmd_clean ;;
    status) cmd_status ;;
    *)      usage ;;
esac
