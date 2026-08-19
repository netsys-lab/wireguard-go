#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
check_root


normalize_ipv6() {
    python3 - "$1" <<'PYIP'
import ipaddress
import sys
print(ipaddress.IPv6Address(sys.argv[1]))
PYIP
}

namespace_has_ipv6() {
    local ns="$1" iface="$2" expected="$3"
    local actual

    while read -r actual; do
        [[ -n "$actual" ]] || continue
        if python3 - "$expected" "$actual" <<'PYIP'
import ipaddress
import sys
try:
    expected = ipaddress.IPv6Address(sys.argv[1])
    actual = ipaddress.IPv6Address(sys.argv[2].split('/', 1)[0])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if expected == actual else 1)
PYIP
        then
            return 0
        fi
    done < <(ip netns exec "$ns" ip -o -6 addr show dev "$iface" scope global | awk '{print $4}')

    return 1
}

cleanup_reference_scitra() {
    if [[ -s "$REFERENCE_SCITRA_PID_FILE" ]]; then
        kill "$(cat "$REFERENCE_SCITRA_PID_FILE")" 2>/dev/null || true
    fi
    if is_namespace_running "$SERVER_NS"; then
        ip netns exec "$SERVER_NS" pkill -f "scitra-tun.*$REFERENCE_SCITRA_IP" 2>/dev/null || true
        ip netns exec "$SERVER_NS" ip addr del "$REFERENCE_SCITRA_IP/32" dev "$WG_SERVER_IFACE" 2>/dev/null || true
        # A TUN interface disappears when the reference process exits; wait a
        # moment so its fc00::/8 route is gone before continuing.
        for _ in {1..20}; do
            ip netns exec "$SERVER_NS" ip link show "$SCITRA_TUN_IFACE" >/dev/null 2>&1 || break
            sleep .1
        done
    fi
    rm -f "$REFERENCE_SCITRA_PID_FILE" "$REFERENCE_SCITRA_IP_FILE"
}

stop_scitra() {
    cleanup_reference_scitra
    if is_namespace_running "$SCITRA_NS"; then
        ip netns exec "$SCITRA_NS" pkill -f 'scitra-tun' 2>/dev/null || true
        ip netns exec "$SCITRA_NS" pkill -f 'python3 -m http.server' 2>/dev/null || true
    fi
    rm -f "$SCITRA_PID_FILE" "$WEBSITE_PID_FILE" "$PLAIN_WEBSITE_PID_FILE" "$WEBSITE_IP_FILE"
}

start_plain_website() {
    log_info "Starting plain-IP health website on $SCITRA_HOST_IP:$PLAIN_WEBSITE_PORT ..."
    : > "$LOGS_DIR/plain-website.log"
    ip netns exec "$SCITRA_NS" bash -c "
        nohup python3 -m http.server '$PLAIN_WEBSITE_PORT' \\
            --bind '$SCITRA_HOST_IP' \\
            --directory '$PLAIN_WEBSITE_DIR' \\
            > '$LOGS_DIR/plain-website.log' 2>&1 &
        echo \$! > '$PLAIN_WEBSITE_PID_FILE'
    "

    # Pure underlay/HTTP check: no Scitra, no SCION, no custom translator.
    wait_for 10 "plain-IP website" \
        "ip netns exec '$SERVER_NS' curl -fsS 'http://$SCITRA_HOST_IP:$PLAIN_WEBSITE_PORT/' | grep -q 'Plain IP Test Server'"
    log_success "Plain-IP website reachable from $SERVER_NS: http://$SCITRA_HOST_IP:$PLAIN_WEBSITE_PORT/"
}

verify_target_scion_control_plane() {
    # Full bidirectional path readiness is already enforced by 07-scion.sh.
    # Here we only verify that ScitraServer can still reach its target-AS daemon
    # immediately before starting Scitra-TUN.
    log_info "Checking target-AS daemon from $SCITRA_NS ..."
    ip netns exec "$SCITRA_NS" ping -c1 -W2 "$SCITRA_DAEMON_IP" >/dev/null
    wait_for 10 "target daemon TCP API" \
        "ip netns exec '$SCITRA_NS' bash -c '</dev/tcp/$SCITRA_DAEMON_IP/$SCITRA_DAEMON_PORT'"
    log_success "Target-AS daemon reachable at $SCITRA_DAEMON_ADDR"
    log_success "Bidirectional SCION path readiness was already verified before Scitra startup"
}

start_and_verify_scitra() {
    log_info "Starting Scitra-TUN for $TARGET_IA,$SCITRA_HOST_IP ..."
    : > "$LOGS_DIR/scitra-tun.log"
    ip netns exec "$SCITRA_NS" bash -c "
        export SCION_DAEMON_ADDRESS='$SCITRA_DAEMON_ADDR'
        nohup scitra-tun '$SCITRA_HOST_IFACE' '$SCITRA_HOST_IP' \\
            -d '$SCITRA_DAEMON_ADDR' \\
            --ports '$SCITRA_PORT' \\
            --scmp \\
            --log-level debug \\
            > '$LOGS_DIR/scitra-tun.log' 2>&1 &
        echo \$! > '$SCITRA_PID_FILE'
    "

    # 1) Process must remain alive.
    wait_for 10 "Scitra-TUN process" \
        "ip netns exec '$SCITRA_NS' pgrep -f 'scitra-tun' >/dev/null"
    log_success "Scitra-TUN process is running"

    # 2) Scitra must create its TUN interface.
    wait_for 10 "Scitra TUN interface" \
        "ip netns exec '$SCITRA_NS' ip link show '$SCITRA_TUN_IFACE' >/dev/null 2>&1"
    log_success "Scitra TUN interface '$SCITRA_TUN_IFACE' exists"

    # 3) TUN must be UP.
    if ! ip netns exec "$SCITRA_NS" ip -o link show dev "$SCITRA_TUN_IFACE" | grep -q '<[^>]*UP[^>]*>'; then
        log_error "Scitra TUN interface '$SCITRA_TUN_IFACE' exists but is not UP"
        return 1
    fi
    log_success "Scitra TUN interface '$SCITRA_TUN_IFACE' is UP"

    # 4) Expected mapped IPv6 must be assigned by Scitra.
    # scion2ip may print the final 32 bits in mixed IPv4 notation, e.g.
    #   fc00:...:ffff:10.30.34.100
    # while Linux prints the exact same IPv6 address in hexadecimal, e.g.
    #   fc00:...:ffff:a1e:2264
    # Compare parsed IPv6 addresses instead of their textual representation.
    local mapped_raw mapped
    mapped_raw="$(scion2ip "$TARGET_IA,$SCITRA_HOST_IP")"
    mapped="$(normalize_ipv6 "$mapped_raw")"
    echo "$mapped" > "$WEBSITE_IP_FILE"
    wait_for 10 "mapped IPv6 on Scitra TUN" \
        "namespace_has_ipv6 '$SCITRA_NS' '$SCITRA_TUN_IFACE' '$mapped'"
    log_success "Expected mapped IPv6 is present on '$SCITRA_TUN_IFACE': $mapped"

    # 5) Scitra documents that fc00::/8 is routed through its TUN interface.
    if ! ip netns exec "$SCITRA_NS" ip -6 route show | grep -Eq "^fc00::/8 .*dev $SCITRA_TUN_IFACE([[:space:]]|$)"; then
        log_error "Expected route fc00::/8 via '$SCITRA_TUN_IFACE' is missing"
        ip netns exec "$SCITRA_NS" ip -6 route show >&2 || true
        return 1
    fi
    log_success "Scitra route fc00::/8 -> $SCITRA_TUN_IFACE is installed"

    # 6) Re-check process after initialization to catch immediate crashes.
    sleep 1
    if ! ip netns exec "$SCITRA_NS" pgrep -f 'scitra-tun' >/dev/null; then
        log_error "Scitra-TUN exited after initialization"
        tail -n 50 "$LOGS_DIR/scitra-tun.log" >&2 || true
        return 1
    fi
    log_success "Scitra-TUN remains running after initialization"
}

start_scion_website() {
    local mapped
    mapped="$(cat "$WEBSITE_IP_FILE")"
    log_info "Starting SCION target website on [$mapped]:$SCITRA_PORT ..."
    : > "$LOGS_DIR/scion-website.log"

    # Bind specifically to Scitra's mapped TUN address. This keeps the normal
    # IPv4 health website separate from the SCION-facing application endpoint.
    ip netns exec "$SCITRA_NS" bash -c "
        nohup python3 -m http.server '$SCITRA_PORT' \\
            --bind '$mapped' \\
            --directory '$SCION_WEBSITE_DIR' \\
            > '$LOGS_DIR/scion-website.log' 2>&1 &
        echo \$! > '$WEBSITE_PID_FILE'
    "

    wait_for 10 "SCION website bound to mapped IPv6" \
        "ip netns exec '$SCITRA_NS' curl -g -6 -fsS 'http://[$mapped]:$SCITRA_PORT/' | grep -q 'SCION Test Server'"
    log_success "SCION target website locally reachable on http://[$mapped]:$SCITRA_PORT/"
}

verify_scion_data_plane_without_custom_translator() {
    local target="$TARGET_IA,$SCITRA_HOST_IP"
    log_info "Reference SCION data-plane check WITHOUT custom translator: scion ping $target"

    # Scitra-TUN is started with --scmp, so it can answer SCMP echo requests.
    # The command runs directly in the Server namespace with the source-AS
    # daemon. The custom wg-client has not been started yet at this point in the
    # master startup flow. A successful reply validates the SCION data plane to
    # Scitra and the return path independently of our translation implementation.
    if ! ip netns exec "$SERVER_NS" "$SCION_DIR/bin/scion" ping \
        --sciond "$SOURCE_DAEMON_ADDR" \
        --count 2 \
        --timeout 2s \
        "$target" \
        > "$LOGS_DIR/scion-reference-ping.log" 2>&1; then
        log_error "Reference SCION ping to Scitra-TUN failed (custom translator was NOT involved)"
        tail -n 50 "$LOGS_DIR/scion-reference-ping.log" >&2 || true
        return 1
    fi
    log_success "Reference SCION data plane to Scitra-TUN works without the custom translator"
}

verify_reference_tcp_path_without_custom_translator() {
    local target_mapped source_mapped_raw source_mapped
    target_mapped="$(cat "$WEBSITE_IP_FILE")"
    source_mapped_raw="$(scion2ip "$SOURCE_IA,$REFERENCE_SCITRA_IP")"
    source_mapped="$(normalize_ipv6 "$source_mapped_raw")"

    log_info "Starting SECOND/reference Scitra-TUN in $SERVER_NS for a known-good path ($SOURCE_IA,$REFERENCE_SCITRA_IP) ..."
    cleanup_reference_scitra
    echo "$source_mapped" > "$REFERENCE_SCITRA_IP_FILE"
    ip netns exec "$SERVER_NS" ip addr add "$REFERENCE_SCITRA_IP/32" dev "$WG_SERVER_IFACE"
    : > "$LOGS_DIR/reference-source-scitra.log"

    ip netns exec "$SERVER_NS" bash -c "
        export SCION_DAEMON_ADDRESS='$SOURCE_DAEMON_ADDR'
        nohup scitra-tun '$WG_SERVER_IFACE' '$REFERENCE_SCITRA_IP' \
            -d '$SOURCE_DAEMON_ADDR' \
            --log-level debug \
            > '$LOGS_DIR/reference-source-scitra.log' 2>&1 &
        echo \$! > '$REFERENCE_SCITRA_PID_FILE'
    "

    wait_for 10 "reference source Scitra process" \
        "kill -0 \$(cat '$REFERENCE_SCITRA_PID_FILE') 2>/dev/null"
    wait_for 10 "reference source Scitra TUN" \
        "ip netns exec '$SERVER_NS' ip link show '$SCITRA_TUN_IFACE' >/dev/null 2>&1"
    wait_for 10 "reference source mapped IPv6" \
        "namespace_has_ipv6 '$SERVER_NS' '$SCITRA_TUN_IFACE' '$source_mapped'"

    log_info "Reference TCP check: official Scitra-TUN -> SCION -> target Scitra-TUN -> HTTP"
    if ! ip netns exec "$SERVER_NS" curl -g -6 -fsS --connect-timeout 5 --max-time 15 \
        "http://[$target_mapped]:$SCITRA_PORT/" \
        > "$LOGS_DIR/reference-scion-http.html" 2> "$LOGS_DIR/reference-scion-http.stderr"; then
        log_error "Reference SCION HTTP path failed while the custom translator was NOT running"
        cat "$LOGS_DIR/reference-scion-http.stderr" >&2 || true
        cleanup_reference_scitra
        return 1
    fi
    if ! grep -q 'SCION Test Server' "$LOGS_DIR/reference-scion-http.html"; then
        log_error "Reference SCION HTTP response did not contain the expected marker"
        cleanup_reference_scitra
        return 1
    fi

    log_success "Reference SCION HTTP/TCP path works end-to-end with official Scitra on both ends; custom translator was not running"
    log_success "Reference Scitra-TUN remains running in $SERVER_NS for side-by-side debugging"
}

status() {
    local mapped="<not-ready>" ref_mapped="<not-ready>"
    [[ -s "$WEBSITE_IP_FILE" ]] && mapped="$(cat "$WEBSITE_IP_FILE")"
    [[ -s "$REFERENCE_SCITRA_IP_FILE" ]] && ref_mapped="$(cat "$REFERENCE_SCITRA_IP_FILE")"

    echo "Target Scitra namespace ($SCITRA_NS):"
    ip netns exec "$SCITRA_NS" ip -br addr 2>/dev/null || true
    echo; echo "Target processes:"
    ip netns exec "$SCITRA_NS" pgrep -af 'scitra-tun|http.server' 2>/dev/null || true
    echo; echo "Target IPv6 routes:"
    ip netns exec "$SCITRA_NS" ip -6 route 2>/dev/null || true

    echo; echo "Reference Scitra in $SERVER_NS:"
    echo "  Host endpoint:   $SOURCE_IA,$REFERENCE_SCITRA_IP"
    echo "  Mapped IPv6:     $ref_mapped"
    ip netns exec "$SERVER_NS" pgrep -af "scitra-tun.*$REFERENCE_SCITRA_IP" 2>/dev/null || true
    ip netns exec "$SERVER_NS" ip -6 addr show dev "$SCITRA_TUN_IFACE" 2>/dev/null || true
    ip netns exec "$SERVER_NS" ip -6 route show fc00::/8 2>/dev/null || true

    echo
    echo "Plain-IP website:  http://$SCITRA_HOST_IP:$PLAIN_WEBSITE_PORT/"
    echo "SCION website:     http://[$mapped]:$SCITRA_PORT/"
}

case "${1:-}" in
    up)
        log_step "Scitra-TUN + websites + reference health checks"
        stop_scitra
        start_plain_website
        verify_target_scion_control_plane
        start_and_verify_scitra
        start_scion_website
        verify_scion_data_plane_without_custom_translator
        verify_reference_tcp_path_without_custom_translator
        log_success "Reference SCION + Scitra + HTTP path is READY and reference Scitra remains running; custom translator has not been tested"
        ;;
    down) stop_scitra ;;
    status) status ;;
    logs) tail -100 "$LOGS_DIR/plain-website.log" "$LOGS_DIR/scion-website.log" "$LOGS_DIR/scitra-tun.log" "$LOGS_DIR/reference-source-scitra.log" "$LOGS_DIR/scion-reference-ping.log" 2>/dev/null || true ;;
    *) echo "Usage: $0 {up|down|status|logs}"; exit 2 ;;
esac
