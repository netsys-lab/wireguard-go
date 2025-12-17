#!/bin/bash

# Namespaces
SERVER="Server"
CLIENT="Client"

# Interfaces
VETH1="veth1"
VETH2="veth2"

# IPs
SERVER_IP="10.0.0.1/24"
CLIENT_IP="10.0.0.2/24"

set -e  # Exit on error

function up() {
    echo "-- Creating namespaces: $SERVER and $CLIENT"
    sudo ip netns add $SERVER
    sudo ip netns add $CLIENT

    echo "-- Creating veth pair: $VETH1 <-> $VETH2"
    sudo ip link add $VETH1 type veth peer name $VETH2

    echo "-- Assigning veth interfaces to namespaces"
    sudo ip link set $VETH1 netns $SERVER
    sudo ip link set $VETH2 netns $CLIENT

    echo "-- Assigning IPs and bringing interfaces up"
    sudo ip netns exec $SERVER ip addr add $SERVER_IP dev $VETH1
    sudo ip netns exec $CLIENT ip addr add $CLIENT_IP dev $VETH2

    sudo ip netns exec $SERVER ip link set $VETH1 up
    sudo ip netns exec $CLIENT ip link set $VETH2 up

    sudo ip netns exec $SERVER ip link set lo up
    sudo ip netns exec $CLIENT ip link set lo up
    
    sudo ip netns exec Client ip route add default via 10.0.0.1 dev veth2
    sudo ip netns exec Server ip route add default via 10.0.0.2 dev veth1

    echo "-- Setup complete."
    echo "-- Test with: sudo ip netns exec $CLIENT ping -c 3 ${SERVER_IP%/*}"
}

function down() {
    echo "Deleting namespaces (and their interfaces)"
    sudo ip netns del $SERVER || echo "Namespace $SERVER not found."
    sudo ip netns del $CLIENT || echo "Namespace $CLIENT not found."

    # Just in case the veths are still in the root namespace
    sudo ip link del $VETH1 2>/dev/null || true
    sudo ip link del $VETH2 2>/dev/null || true

    echo "-- Cleanup complete."
}

case "$1" in
    up)
        up
        ;;
    down)
        down
        ;;
    *)
        echo "Usage: $0 {up|down}"
        exit 1
        ;;
esac
