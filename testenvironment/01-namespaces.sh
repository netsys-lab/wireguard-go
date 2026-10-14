#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
check_root

cleanup_namespaces() {
    log_info "Cleaning namespaces..."
    for ns in "$SCITRA_NS" "$CLIENT_NS" "$SERVER_NS"; do
        if is_namespace_running "$ns"; then
            # Kill every process still attached to the namespace. This also
            # handles stale supervisor/SCION processes from an interrupted run.
            mapfile -t _pids < <(ip netns pids "$ns" 2>/dev/null || true)
            if (( ${#_pids[@]} )); then kill -9 "${_pids[@]}" 2>/dev/null || true; fi
        fi
    done
    ip netns del "$SCITRA_NS" 2>/dev/null || true
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
    ip link del "$SERVER_VETH_IFACE" 2>/dev/null || true
    ip link del "$CLIENT_VETH_IFACE" 2>/dev/null || true
    ip link del "$SCITRA_SERVER_IFACE" 2>/dev/null || true
    ip link del "$SCITRA_HOST_IFACE" 2>/dev/null || true
    rm -f "$SCITRA_PID_FILE" "$WEBSITE_PID_FILE" "$WEBSITE_IP_FILE"
}

create_namespaces() {
    for ns in "$SERVER_NS" "$CLIENT_NS" "$SCITRA_NS"; do
        ip netns add "$ns"
        ip netns exec "$ns" ip link set lo up
        log_success "Created $ns"
    done
}

create_links() {
    ip link add "$SERVER_VETH_IFACE" type veth peer name "$CLIENT_VETH_IFACE"
    ip link set "$SERVER_VETH_IFACE" netns "$SERVER_NS"
    ip link set "$CLIENT_VETH_IFACE" netns "$CLIENT_NS"

    ip link add "$SCITRA_SERVER_IFACE" type veth peer name "$SCITRA_HOST_IFACE"
    ip link set "$SCITRA_SERVER_IFACE" netns "$SERVER_NS"
    ip link set "$SCITRA_HOST_IFACE" netns "$SCITRA_NS"
}

configure_links() {
    ip netns exec "$SERVER_NS" ip addr add "$SERVER_VETH_IP" dev "$SERVER_VETH_IFACE"
    ip netns exec "$SERVER_NS" ip link set "$SERVER_VETH_IFACE" up
    ip netns exec "$CLIENT_NS" ip addr add "$CLIENT_VETH_IP" dev "$CLIENT_VETH_IFACE"
    ip netns exec "$CLIENT_NS" ip link set "$CLIENT_VETH_IFACE" up

    # The Server-side veth gets the daemon IP as its primary address. BR aliases
    # are added after topology generation by 04-topo_change.sh.
    ip netns exec "$SERVER_NS" ip addr add "$SCITRA_DAEMON_IP/24" dev "$SCITRA_SERVER_IFACE"
    ip netns exec "$SERVER_NS" ip link set "$SCITRA_SERVER_IFACE" up
    ip netns exec "$SCITRA_NS" ip addr add "$SCITRA_HOST_IP_CIDR" dev "$SCITRA_HOST_IFACE"
    ip netns exec "$SCITRA_NS" ip link set "$SCITRA_HOST_IFACE" up
}

setup_tun() {
    for ns in "$SERVER_NS" "$CLIENT_NS" "$SCITRA_NS"; do
        ip netns exec "$ns" bash -c 'mkdir -p /dev/net; [[ -c /dev/net/tun ]] || mknod /dev/net/tun c 10 200; chmod 666 /dev/net/tun'
    done
}

verify() {
    for ns in "$SERVER_NS" "$CLIENT_NS" "$SCITRA_NS"; do is_namespace_running "$ns" || return 1; done
    ip netns exec "$CLIENT_NS" ping -c1 -W1 "${SERVER_VETH_IP%%/*}" >/dev/null
    ip netns exec "$SCITRA_NS" ping -c1 -W1 "$SCITRA_DAEMON_IP" >/dev/null
    log_success "Namespace networking verified"
}

status() {
    ip netns list
    echo; echo "[$SERVER_NS]"; ip netns exec "$SERVER_NS" ip -br addr || true
    echo; echo "[$CLIENT_NS]"; ip netns exec "$CLIENT_NS" ip -br addr || true
    echo; echo "[$SCITRA_NS]"; ip netns exec "$SCITRA_NS" ip -br addr || true
}

case "${1:-}" in
    up)
        log_step "Namespaces"
        create_directories; cleanup_namespaces; create_namespaces; create_links; configure_links; setup_tun; verify
        ;;
    down) cleanup_namespaces ;;
    status) status ;;
    *) echo "Usage: $0 {up|down|status}"; exit 2 ;;
esac
