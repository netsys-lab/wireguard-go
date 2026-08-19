#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

website_ip() {
    [[ -s "$WEBSITE_IP_FILE" ]] || { log_error "Mapped website IP not known. Run the environment first."; return 1; }
    cat "$WEBSITE_IP_FILE"
}

test_plain_ip() {
    log_info "Health test: plain-IP website (NO translator, NO SCION, NO Scitra-TUN)"
    ip netns exec "$SERVER_NS" curl -fsS --max-time 5 "http://$SCITRA_HOST_IP:$PLAIN_WEBSITE_PORT/" | grep -q 'Plain IP Test Server'
    log_success "Plain-IP website PASS"
}

test_wireguard() {
    log_info "Health test: basic WireGuard reachability"
    ip netns exec "$CLIENT_NS" ping -c2 -W2 "${WG_SERVER_IP%%/*}" >/dev/null
    log_success "WireGuard connectivity PASS"
}

test_scitra_local() {
    local ip; ip="$(website_ip)"
    log_info "Health test: SCION website locally through Scitra-TUN (does NOT test custom translator)"
    ip netns exec "$SCITRA_NS" curl -g -6 -fsS --max-time 5 "http://[$ip]:$SCITRA_PORT/" | grep -q 'SCION Test Server'
    log_success "Local Scitra website PASS"
}

test_end_to_end() {
    local ip out
    ip="$(website_ip)"
    log_info "ACTUAL TEST: Client -> custom Translator -> WireGuard -> SCION -> Scitra -> HTTP"
    out="$(ip netns exec "$CLIENT_NS" curl -g -fsS -v --connect-timeout 10 --max-time 30 "http://[$ip]:$SCITRA_PORT/" 2>"$LOGS_DIR/curl-e2e.stderr")" || {
        log_error "End-to-end curl FAILED"
        cat "$LOGS_DIR/curl-e2e.stderr" >&2 || true
        return 1
    }
    printf '%s\n' "$out" > "$LOGS_DIR/curl-e2e.html"
    grep -q 'This page was delivered through Scitra-TUN.' <<<"$out" || {
        log_error "HTTP response did not contain expected SCION marker"
        return 1
    }
    log_success "END-TO-END HTTP PASS"
}

summary() {
    local ip="<not-ready>"
    [[ -s "$WEBSITE_IP_FILE" ]] && ip="$(cat "$WEBSITE_IP_FILE")"
    cat <<EOF2

============================================================
 SCION / SCITRA DEBUG ENVIRONMENT READY
============================================================
Client namespace:      $CLIENT_NS
SCION namespace:       $SERVER_NS
Scitra namespace:      $SCITRA_NS
Source IA:             $SOURCE_IA
Target IA:             $TARGET_IA
Scitra host:           $SCITRA_HOST_IP

Plain-IP website:
  http://$SCITRA_HOST_IP:$PLAIN_WEBSITE_PORT/
  Check from Server namespace:
  sudo ip netns exec $SERVER_NS curl -v "http://$SCITRA_HOST_IP:$PLAIN_WEBSITE_PORT/"

SCION website target:
  SCION endpoint: $TARGET_IA,$SCITRA_HOST_IP
  Mapped IPv6:    $ip
  URL:            http://[$ip]:$SCITRA_PORT/

Startup has already verified a reference SCION HTTP/TCP path with official Scitra-TUN on both sides
BEFORE the custom wg-client was started. The source-side reference Scitra remains running in $SERVER_NS.

Known-good reference request (official Scitra -> SCION -> target Scitra -> HTTP):
  sudo ip netns exec $SERVER_NS curl -g -6 -v "http://[$ip]:$SCITRA_PORT/"

Custom translator request (actual system under test):
  sudo ip netns exec $CLIENT_NS curl -g -6 -v "http://[$ip]:$SCITRA_PORT/"

The custom translator end-to-end request is NOT run during setup.
Run it explicitly with:
  sudo ./testenvironment.bash test

Detailed capture/debug commands:
  $TESTENV_DIR/DEBUGGING.md

Logs:
  $LOGS_DIR
============================================================
EOF2
}

case "${1:-test}" in
    test) log_step "Manual end-to-end translator test"; test_end_to_end; summary ;;
    health) log_step "Local health tests"; test_plain_ip; test_wireguard; test_scitra_local; summary ;;
    plain) test_plain_ip ;;
    scitra-local) test_scitra_local ;;
    curl|e2e) test_end_to_end; summary ;;
    summary) summary ;;
    *) echo "Usage: $0 {test|health|plain|scitra-local|curl|summary}"; exit 2 ;;
esac
