#!/usr/bin/env bash
#===============================================================================
# Step 3: SCION Infrastructure
# Wrapper script that orchestrates SCION topology, bootstrap, and services
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

#-------------------------------------------------------------------------------
# Usage
#-------------------------------------------------------------------------------

usage() {
    cat << EOF
Usage: $0 <command>

This script is a wrapper around the SCION setup:
  03a-topology.sh  - Generate SCION topology only
  03b-bootstrap.sh  - Start/stop bootstrap server
  03c-scion.sh     - Start/stop SCION services

For proper setup order, use testenv.sh instead:
  sudo ./testenv.sh up

The correct order is:
1. Generate topology (03a-topology.sh generate)
2. Start bootstrap (03b-bootstrap.sh up)
3. Start WireGuard (04-wireguard.sh up) 
4. Start SCION (03c-scion.sh up)

Examples:
  # Generate topology only
  sudo $SCRIPT_DIR/03a-topology.sh generate

  # Start bootstrap server
  sudo $SCRIPT_DIR/03b-bootstrap.sh up

  # Start SCION services
  sudo $SCRIPT_DIR/03c-scion.sh up

  # Full SCION setup (in order)
  sudo $SCRIPT_DIR/03a-topology.sh generate
  sudo $SCRIPT_DIR/03b-bootstrap.sh up
  # (start wireguard here)
  sudo $SCRIPT_DIR/03c-scion.sh up
EOF
}

# If called directly with no args, show usage
if [[ $# -eq 0 ]]; then
    usage
    exit 0
fi
