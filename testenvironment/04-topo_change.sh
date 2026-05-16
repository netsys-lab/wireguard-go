#!/usr/bin/env bash
set -euo pipefail

source ./config.sh

: "${SCION_CONFIG_DIR:?SCION_CONFIG_DIR is not set}"
: "${DEAMON_CONFIG_FILE:?DEAMON_CONFIG_FILE is not set}"
: "${SERVER_VETH_IP:?SERVER_VETH_IP is not set}"
: "${SERVER_65413_sciond_addr:?SERVER_65413_sciond_addr is not set}"
: "${SERVER_NS:?SERVER_NS is not set}"

GENFILE="$SCION_CONFIG_DIR"

# BR internal address
OLD_BR_IP="127.0.0.25"
NEW_BR_IP="${WG_SERVER_IP%%/*}"          # usually 10.0.0.1

# sciond / control / discovery reachable address
OLD_DAEMON_IP="127.0.0.27"
OLD_CS_IP="127.0.0.26"
NEW_SERVICE_IP="${SERVER_65413_sciond_addr%%/*}"   # usually 10.0.0.3

echo "Patching SCION topology in $GENFILE"

# BR internal_addr: 127.0.0.25 -> 10.0.0.1
sed -i.bak "s|${OLD_BR_IP}|${NEW_BR_IP}|g" "$GENFILE/topology.json"
echo "Replaced BR IP $OLD_BR_IP -> $NEW_BR_IP in topology.json"

# Control + Discovery service: 127.0.0.26:31004 -> 10.0.0.3:31004
sed -i.bak "s|${OLD_CS_IP}:31004|${NEW_SERVICE_IP}:31004|g" "$GENFILE/topology.json"
echo "Replaced Control/Discovery $OLD_CS_IP:31004 -> $NEW_SERVICE_IP:31004 in topology.json"

# Make service IP available in Server namespace
sudo ip netns exec "$SERVER_NS" ip addr add "${NEW_SERVICE_IP}/8" dev lo 2>/dev/null || true
echo "Added $NEW_SERVICE_IP/8 to lo in namespace $SERVER_NS"

# sciond config: 127.0.0.27:30255 -> 10.0.0.3:30255
sed -i.bak "s|${OLD_DAEMON_IP}:30255|${NEW_SERVICE_IP}:30255|g" "$DEAMON_CONFIG_FILE"
echo "Replaced daemon $OLD_DAEMON_IP:30255 -> $NEW_SERVICE_IP:30255 in $DEAMON_CONFIG_FILE"

echo "Done."
