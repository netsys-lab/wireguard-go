#!/usr/bin/env bash
#===============================================================================
# Step 6: Topology Change
# Changes the SCION topology generated files
#===============================================================================

set -euo pipefail

# Load variables from previous config script
source ./config.sh

# Required variables
: "${SCION_CONFIG_DIR:?SCION_CONFIG_DIR is not set}"
: "${DEAMON_CONFIG_FILE:?DEAMON_CONFIG_FILE is not set}"
: "${SERVER_VETH_IP:?SERVER_VETH_IP is not set}"
: "${SERVER_65413_sciond_addr:?SERVER_65413_sciond_addr is not set}"

GENFILE="$SCION_CONFIG_DIR"

OLD_IP="127.0.0.25"
NEW_IP="${SERVER_VETH_IP%%/*}"

OLD_DAEMON_IP="127.0.0.27"
NEW_DAEMON_IP="${SERVER_65413_sciond_addr%%/*}"

# Replace IP in topology.json
sed -i.bak "s|${OLD_IP}|${NEW_IP}|g" "$GENFILE/topology.json"

echo "Replaced $OLD_IP with $NEW_IP in $GENFILE/topology.json"

# Add IP to loopback interface
sudo ip netns exec "$SERVER_NS" ip addr add "$NEW_DAEMON_IP" dev lo || true

echo "Added $NEW_DAEMON_IP to loopback interface"

# Replace daemon IP in daemon config file
sed -i.bak "s|${OLD_DAEMON_IP}:30255|${NEW_DAEMON_IP}:30255|g" "$DEAMON_CONFIG_FILE"

echo "Replaced $OLD_DAEMON_IP:30255 with $NEW_DAEMON_IP:30255 in $DEAMON_CONFIG_FILE"
