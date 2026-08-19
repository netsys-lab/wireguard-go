#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
check_root

load_keys() {
    [[ -s "$KEYS_DIR/server_private" && -s "$KEYS_DIR/client_private" ]] || { log_error "WireGuard keys missing. Run 02-build.sh"; return 1; }
    SERVER_PRIVATE_HEX="$(base64 -d "$KEYS_DIR/server_private" | xxd -p -c 256)"
    SERVER_PUBLIC_HEX="$(base64 -d "$KEYS_DIR/server_public" | xxd -p -c 256)"
    CLIENT_PRIVATE_HEX="$(base64 -d "$KEYS_DIR/client_private" | xxd -p -c 256)"
    CLIENT_PUBLIC_HEX="$(base64 -d "$KEYS_DIR/client_public" | xxd -p -c 256)"
}

wait_socket() {
    local iface="$1"
    for _ in {1..50}; do [[ -S "/var/run/wireguard/$iface.sock" ]] && return 0; sleep .2; done
    return 1
}

kill_iface() {
    local ns="$1" iface="$2"
    if is_namespace_running "$ns"; then
        ip netns exec "$ns" pkill -f "wireguard-go.*$iface" 2>/dev/null || true
        ip netns exec "$ns" ip link del "$iface" 2>/dev/null || true
    fi
    rm -f "/var/run/wireguard/$iface.sock"
}

latest_handshake_epoch() {
    local ns="$1" iface="$2"
    ip netns exec "$ns" wg show "$iface" latest-handshakes 2>/dev/null | awk 'NR==1 {print $2}'
}

verify_wireguard_handshake() {
    local epoch=""
    epoch="$(latest_handshake_epoch "$CLIENT_NS" "$WG_CLIENT_IFACE" || true)"
    if [[ ! "$epoch" =~ ^[0-9]+$ ]] || (( epoch == 0 )); then
        log_error "WireGuard ping succeeded but no completed handshake is reported by $WG_CLIENT_IFACE"
        ip netns exec "$CLIENT_NS" wg show "$WG_CLIENT_IFACE" >&2 || true
        return 1
    fi
    local now age
    now="$(date +%s)"; age=$((now - epoch))
    (( age < 0 )) && age=0
    log_success "WireGuard handshake established (${age}s ago)"
}

start_server() {
    load_keys; load_runtime_env
    kill_iface "$SERVER_NS" "$WG_SERVER_IFACE"
    : > "$LOGS_DIR/wg-server.log"
    ip netns exec "$SERVER_NS" bash -c "
        export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
        export LOG_LEVEL='$LOG_LEVEL'
        export SCION_ENABLED=false
        exec '$BIN_DIR/wireguard-go' --foreground '$WG_SERVER_IFACE' >> '$LOGS_DIR/wg-server.log' 2>&1
    " &
    wait_for 15 "wg-server interface" "ip netns exec '$SERVER_NS' ip link show '$WG_SERVER_IFACE'"
    wait_socket "$WG_SERVER_IFACE" || { log_error "wg-server UAPI socket missing"; return 1; }

    ip netns exec "$SERVER_NS" bash -c "printf '%s\n' 'set=1' 'private_key=$SERVER_PRIVATE_HEX' 'listen_port=51820' | socat - UNIX-CONNECT:/var/run/wireguard/$WG_SERVER_IFACE.sock"
    ip netns exec "$SERVER_NS" bash -c "printf '%s\n' \
        'set=1' \
        'public_key=$CLIENT_PUBLIC_HEX' \
        'allowed_ip=10.0.0.0/8' \
        'allowed_ip=${WG_CLIENT_IPV6}' \
        'persistent_keepalive_interval=25' \
        | socat - UNIX-CONNECT:/var/run/wireguard/$WG_SERVER_IFACE.sock"

    ip netns exec "$SERVER_NS" ip addr add "$WG_SERVER_IP" dev "$WG_SERVER_IFACE" 2>/dev/null || true
    # All source-AS BR internal addresses must exist before SCION starts.
    if declare -p SOURCE_BR_IPS >/dev/null 2>&1; then
        for addr in "${SOURCE_BR_IPS[@]}"; do
            [[ "$addr" == "${WG_SERVER_IP%%/*}" ]] && continue
            ip netns exec "$SERVER_NS" ip addr add "$addr/32" dev "$WG_SERVER_IFACE" 2>/dev/null || true
        done
    fi

    # The source Control/Discovery Service must also have a non-loopback address
    # that the Client namespace can reach through WireGuard. Without this alias,
    # the bootstrapped translator receives e.g. 127.0.0.44:31000 and connects to
    # its own Client loopback instead of the source-AS control service.
    if [[ -n "${SOURCE_CONTROL_IP:-}" ]]; then
        ip netns exec "$SERVER_NS" ip addr add "$SOURCE_CONTROL_IP/32" dev "$WG_SERVER_IFACE" 2>/dev/null || true
    fi

    ip netns exec "$SERVER_NS" ip link set "$WG_SERVER_IFACE" up
    log_success "Vanilla wg-server ready"
    [[ -n "${SOURCE_CONTROL_ADDR:-}" ]] && log_info "Source Control/Discovery Service will bind at $SOURCE_CONTROL_ADDR"
}

start_client() {
    load_keys
    load_runtime_env
    kill_iface "$CLIENT_NS" "$WG_CLIENT_IFACE"
    : > "$LOGS_DIR/wg-client.log"

    local policy_export=""
    if [[ -f "$SCION_POLICY_FILE" ]]; then
        policy_export="export SCION_POLICY_FILE='$SCION_POLICY_FILE'"
    else
        log_warn "No policy file at $SCION_POLICY_FILE; starting translator without SCION_POLICY_FILE"
    fi

    ip netns exec "$CLIENT_NS" bash -c "
        export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
        export LOG_LEVEL='$LOG_LEVEL'
        export SCION_ENABLED=true
        export SCION_CONFIG_DIR='$SCION_CONFIG_DIR'
        export SCION_BOOTSTRAP_URL='$SCION_BOOTSTRAP_URL'
        export SCION_UNDERLAY_PORT='$SCION_UNDERLAY_PORT'
        $policy_export
        exec '$BIN_DIR/wireguard-go' --foreground '$WG_CLIENT_IFACE' >> '$LOGS_DIR/wg-client.log' 2>&1
    " &
    wait_for 15 "wg-client interface" "ip netns exec '$CLIENT_NS' ip link show '$WG_CLIENT_IFACE'"
    wait_socket "$WG_CLIENT_IFACE" || { log_error "wg-client UAPI socket missing"; return 1; }

    ip netns exec "$CLIENT_NS" bash -c "printf '%s\n' 'set=1' 'private_key=$CLIENT_PRIVATE_HEX' 'listen_port=51821' | socat - UNIX-CONNECT:/var/run/wireguard/$WG_CLIENT_IFACE.sock"
    ip netns exec "$CLIENT_NS" bash -c "printf '%s\n' \
        'set=1' \
        'public_key=$SERVER_PUBLIC_HEX' \
        'allowed_ip=0.0.0.0/0' \
        'allowed_ip=::/0' \
        'endpoint=$WG_ENDPOINT' \
        'persistent_keepalive_interval=25' \
        | socat - UNIX-CONNECT:/var/run/wireguard/$WG_CLIENT_IFACE.sock"

    ip netns exec "$CLIENT_NS" ip addr add "$WG_CLIENT_IP" dev "$WG_CLIENT_IFACE" 2>/dev/null || true
    ip netns exec "$CLIENT_NS" ip -6 addr add "$WG_CLIENT_IPV6" dev "$WG_CLIENT_IFACE" 2>/dev/null || true
    ip netns exec "$CLIENT_NS" ip link set "$WG_CLIENT_IFACE" up
    ip netns exec "$CLIENT_NS" ip -6 route replace "$WG_SCION_ROUTE_PREFIX" dev "$WG_CLIENT_IFACE"

    # Ordinary IPv4 traffic only. This establishes and verifies the WireGuard
    # tunnel without sending a SCION-mapped IPv6 packet through our translator.
    wait_for 15 "basic WireGuard tunnel connectivity" \
        "ip netns exec '$CLIENT_NS' ping -c1 -W2 '${WG_SERVER_IP%%/*}' >/dev/null 2>&1"
    verify_wireguard_handshake

    # The bootstrap service is intentionally only reachable on wg-server.
    # Checking it from Client therefore validates: veth underlay -> WireGuard
    # tunnel -> source-AS bootstrap. This is still plain IPv4 and does NOT
    # exercise the fc00::/8 translation path.
    wait_for 15 "bootstrap server through WireGuard" \
        "ip netns exec '$CLIENT_NS' curl -fsS --max-time 3 '$SCION_BOOTSTRAP_URL/topology' >/dev/null 2>&1"
    log_success "Bootstrap server is reachable from $CLIENT_NS through WireGuard"

    # Validate the exact control-service endpoint advertised by the patched
    # bootstrap topology. This remains plain TCP over WireGuard and does not
    # exercise the custom fc00::/8 translation path.
    if [[ -n "${SOURCE_CONTROL_IP:-}" && -n "${SOURCE_CONTROL_PORT:-}" ]]; then
        if ! wait_for 15 "source Control/Discovery Service through WireGuard ($SOURCE_CONTROL_ADDR)" \
            "ip netns exec '$CLIENT_NS' bash -lc 'timeout 3 bash -c \"</dev/tcp/$SOURCE_CONTROL_IP/$SOURCE_CONTROL_PORT\"' >/dev/null 2>&1"; then
            log_error "Client cannot reach source Control/Discovery Service at $SOURCE_CONTROL_ADDR"
            log_error "Check topology-runtime.env, wg-server aliases and the SCION control listener."
            return 1
        fi
        log_success "Source Control/Discovery Service is reachable from $CLIENT_NS at $SOURCE_CONTROL_ADDR"
    fi

    log_success "wg-client is ready; WireGuard + bootstrap + source control service work (SCION translation NOT tested)"
}

baseline_check() {
    log_info "Manual baseline helper: temporarily starting wg-client ..."
    start_client
    log_success "WireGuard baseline passed before SCION startup"
    log_info "Stopping wg-client again so SCION/Scitra reference checks cannot involve our translator ..."
    kill_iface "$CLIENT_NS" "$WG_CLIENT_IFACE"
    log_success "Custom translator stopped for independent SCION/Scitra checks"
}

stop_all() {
    kill_iface "$CLIENT_NS" "$WG_CLIENT_IFACE"
    kill_iface "$SERVER_NS" "$WG_SERVER_IFACE"
}

status() {
    echo "[$SERVER_NS]"; ip netns exec "$SERVER_NS" ip -br addr show "$WG_SERVER_IFACE" 2>/dev/null || true
    ip netns exec "$SERVER_NS" wg show "$WG_SERVER_IFACE" 2>/dev/null || true
    echo "[$CLIENT_NS]"; ip netns exec "$CLIENT_NS" ip -br addr show "$WG_CLIENT_IFACE" 2>/dev/null || true
    ip netns exec "$CLIENT_NS" wg show "$WG_CLIENT_IFACE" 2>/dev/null || true
}

case "${1:-}" in
    server-up) log_step "Vanilla WireGuard server"; start_server ;;
    client-up) log_step "Custom WireGuard / Translator client"; start_client ;;
    client-down) kill_iface "$CLIENT_NS" "$WG_CLIENT_IFACE" ;;
    baseline) log_step "WireGuard baseline before SCION"; baseline_check ;;
    up) log_step "WireGuard"; start_server; start_client ;;
    down) stop_all ;;
    status) status ;;
    logs) tail -100 "$LOGS_DIR/wg-server.log" "$LOGS_DIR/wg-client.log" 2>/dev/null || true ;;
    *) echo "Usage: $0 {server-up|client-up|client-down|baseline|up|down|status|logs}"; exit 2 ;;
esac
