#!/usr/bin/env bash
#===============================================================================
# Step 3a: Generate SCION Topology Only
# Generates the SCION topology files without starting services
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

check_root

log_step "Generating SCION Topology"

#-------------------------------------------------------------------------------
# Generate topology
#-------------------------------------------------------------------------------

generate_topology() {
    log_info "Generating SCION topology..."
    
    cd "$SCION_DIR"
    
    # Check if topology already exists
    if [[ -d "$SCION_DIR/gen/AS64513" ]]; then
        log_info "Topology already exists, skipping generation"
        return 0
    fi
    
    # Generate topology
    if ./scion.sh topology -c "$SCION_TOPOLOGY" 2>&1; then
        log_success "SCION topology generated"
    else
        log_error "Failed to generate SCION topology"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# Verify topology
#-------------------------------------------------------------------------------

verify_topology() {
    log_info "Verifying SCION topology..."
    
    local failed=0
    
    # Check key directories exist
    for as_dir in AS64512 AS64513 AS64514; do
        if [[ -d "$SCION_DIR/gen/$as_dir" ]]; then
            log_success "Found: $as_dir"
        else
            log_error "Missing: $as_dir"
            ((failed++))
        fi
    done
    
    # Check sciond addresses
    if [[ -f "$SCION_DIR/gen/sciond_addresses.json" ]]; then
        log_success "SCIONd addresses file exists"
        cat "$SCION_DIR/gen/sciond_addresses.json"
    else
        log_error "SCIONd addresses file missing"
        ((failed++))
    fi
    
    if [[ $failed -gt 0 ]]; then
        return 1
    fi
    
    return 0
}

#-------------------------------------------------------------------------------
# Clean topology
#-------------------------------------------------------------------------------

clean_topology() {
    log_info "Cleaning SCION topology..."
    
    cd "$SCION_DIR"
    
    if ./scion.sh topo-clean 2>&1; then
        log_success "SCION topology cleaned"
    else
        log_warn "SCION topology clean returned error (may be OK)"
    fi
}

#-------------------------------------------------------------------------------
# Status
#-------------------------------------------------------------------------------

show_status() {
    echo ""
    echo "=== SCION Topology Status ==="
    
    if [[ -d "$SCION_DIR/gen" ]]; then
        echo "AS directories:"
        ls -la "$SCION_DIR/gen"/AS* 2>/dev/null || echo "  (none)"
        
        echo ""
        echo "SCIONd addresses:"
        if [[ -f "$SCION_DIR/gen/sciond_addresses.json" ]]; then
            cat "$SCION_DIR/gen/sciond_addresses.json"
        else
            echo "  (not generated)"
        fi
    else
        echo "  (not generated)"
    fi
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------

cmd_generate() {
    generate_topology
    verify_topology
    show_status
}

cmd_clean() {
    clean_topology
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
    generate   Generate SCION topology only
    clean      Clean SCION topology
    status     Show topology status

Examples:
    sudo $0 generate   # Generate topology
    sudo $0 status    # Show status
    sudo $0 clean    # Clean topology
EOF
}

#-------------------------------------------------------------------------------
# Run
#-------------------------------------------------------------------------------

case "${1:-}" in
    generate) cmd_generate ;;
    clean)    cmd_clean ;;
    status)  cmd_status ;;
    *)       usage ;;
esac
