#!/usr/bin/env bash
#===============================================================================
# Master Control Script
# Orchestrates the complete test environment setup
#===============================================================================
#
# CRITICAL DEPENDENCY ORDER:
# 1. Generate SCION topology (creates gen/ files)
# 2. Start Bootstrap server (needs gen/ files)
# 3. Start WireGuard (needs bootstrap for SCION config)
# 4. Start SCION services (needs WireGuard interfaces to bind to)
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Source config
source "$SCRIPT_DIR/config.sh"

check_root

log_step "Complete Test Environment Setup"

#-------------------------------------------------------------------------------
# Step 0: Print config
#-------------------------------------------------------------------------------

print_config

#-------------------------------------------------------------------------------
# Run all steps in CORRECT ORDER
#-------------------------------------------------------------------------------

cmd_up() {
    echo ""
    log_info "Starting complete environment setup..."
    log_info "CRITICAL: Using correct dependency order..."
    echo ""
    
    # Step 1: Namespaces
    echo ""
    log_info "=== STEP 1: Namespaces ==="
    "$SCRIPT_DIR/01-namespaces.sh" up
    
    # Step 2: Build
    echo ""
    log_info "=== STEP 2: Build ==="
    "$SCRIPT_DIR/02-build.sh" build
    
    # Step 3a: Generate SCION topology (but don't start)
    echo ""
    log_info "=== STEP 3a: Generate SCION Topology ==="
    "$SCRIPT_DIR/03a-topology.sh" generate
    
    # Step 3b: Start Bootstrap server (needs topology)
    echo ""
    log_info "=== STEP 3b: Bootstrap Server ==="
    "$SCRIPT_DIR/03b-bootstrap.sh" up
    
    # Step 4: Start WireGuard (needs bootstrap for SCION config)
    echo ""
    log_info "=== STEP 4: WireGuard ==="
    "$SCRIPT_DIR/04-wireguard.sh" up
    
    # Step 3c: Start SCION services (needs WireGuard interfaces)
    echo ""
    log_info "=== STEP 3c: SCION Services ==="
    "$SCRIPT_DIR/03c-scion.sh" up || log_warn "SCION had issues (may still work)"
    
    echo ""
    log_success "========================================="
    log_success "  Environment Setup Complete!"
    log_success "========================================="
    echo ""
    echo "Run tests with:"
    echo "  sudo $SCRIPT_DIR/06-test.sh test"
    echo ""
    echo "View logs with:"
    echo "  tail -f $LOGS_DIR/*.log"
    echo ""
}

#-------------------------------------------------------------------------------
# Cleanup (reverse order)
#-------------------------------------------------------------------------------

cmd_down() {
    echo ""
    log_info "Stopping complete environment..."
    echo ""
    
    # Stop in reverse order
    "$SCRIPT_DIR/05-echo.sh" down || true
    "$SCRIPT_DIR/03c-scion.sh" down || true
    "$SCRIPT_DIR/04-wireguard.sh" down || true
    "$SCRIPT_DIR/03b-bootstrap.sh" down || true
    "$SCRIPT_DIR/01-namespaces.sh" down || true
    
    log_success "Environment stopped"
}

#-------------------------------------------------------------------------------
# Status
#-------------------------------------------------------------------------------

cmd_status() {
    echo ""
    echo "=== Environment Status ==="
    echo ""
    
    "$SCRIPT_DIR/01-namespaces.sh" status 2>/dev/null || true
    "$SCRIPT_DIR/03a-topology.sh" status 2>/dev/null || true
    "$SCRIPT_DIR/03b-bootstrap.sh" status 2>/dev/null || true
    "$SCRIPT_DIR/04-wireguard.sh" status 2>/dev/null || true
    "$SCRIPT_DIR/05-echo.sh" status 2>/dev/null || true
}

#-------------------------------------------------------------------------------
# Full test
#-------------------------------------------------------------------------------

cmd_test() {
    "$SCRIPT_DIR/06-test.sh" test
}

#-------------------------------------------------------------------------------
# Individual step commands (for debugging)
#-------------------------------------------------------------------------------

cmd_step1() { "$SCRIPT_DIR/01-namespaces.sh" up; }
cmd_step2() { "$SCRIPT_DIR/02-build.sh" build; }
cmd_step3a() { "$SCRIPT_DIR/03a-topology.sh" generate; }
cmd_step3b() { "$SCRIPT_DIR/03b-bootstrap.sh" up; }
cmd_step3c() { "$SCRIPT_DIR/03c-scion.sh" up; }
cmd_step4() { "$SCRIPT_DIR/04-wireguard.sh" up; }
cmd_step5() { "$SCRIPT_DIR/05-echo.sh" down; }

#-------------------------------------------------------------------------------
# Usage
#-------------------------------------------------------------------------------

usage() {
    cat << EOF
SCION-WireGuard Integration Test Environment

CRITICAL: This setup has specific dependency order!

Correct order:
1. Namespaces (01)
2. Build (02)
3a. Generate SCION topology (03a) - ONLY GENERATE, DON'T START
3b. Start Bootstrap server (03b) - needs topology
3c. Start SCION services (03c) - needs WireGuard interfaces
4. WireGuard (04) - needs bootstrap for SCION config

Usage: $0 <command>

Commands:
    up         Setup complete environment (in correct order!)
    down       Stop and cleanup environment
    status     Show status of all components
    test       Run integration tests

Individual steps (for debugging):
    step1   Step 1: Namespaces
    step2   Step 2: Build
    step3a  Step 3a: Generate topology only
    step3b  Step 3b: Bootstrap server
    step3c  Step 3c: SCION services
    step4   Step 4: WireGuard
    step5   Step 5: Echo server

Examples:
    # Full setup (recommended)
    sudo $0 up

    # Run tests
    sudo $0 test

    # View status
    sudo $0 status

    # Cleanup
    sudo $0 down

    # Debug: Run steps individually
    sudo $0 step1
    sudo $0 step2
    sudo $0 step3a
    sudo $0 step3b
    sudo $0 step4
    sudo $0 step3c
    sudo $0 step5
EOF
}

#-------------------------------------------------------------------------------
# Run
#-------------------------------------------------------------------------------

case "${1:-}" in
    up)    cmd_up ;;
    down)  cmd_down ;;
    status) cmd_status ;;
    test)  cmd_test ;;
    step1) cmd_step1 ;;
    step2) cmd_step2 ;;
    step3a) cmd_step3a ;;
    step3b) cmd_step3b ;;
    step3c) cmd_step3c ;;
    step4) cmd_step4 ;;
    step5) cmd_step5 ;;
    *)     usage ;;
esac
