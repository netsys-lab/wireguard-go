#!/bin/bash
set -euo pipefail

# =========================
#  Config (override via env)
# =========================
SERVER_NS="${SERVER_NS:-Server}"
CLIENT_NS="${CLIENT_NS:-Client}"

# Underlay between namespaces (veth)
VETH1="${VETH1:-veth1}"
VETH2="${VETH2:-veth2}"
SERVER_IP_CIDR="${SERVER_IP_CIDR:-10.0.0.1/24}"
CLIENT_IP_CIDR="${CLIENT_IP_CIDR:-10.0.0.2/24}"
SERVER_IP="${SERVER_IP:-10.0.0.1}"
CLIENT_IP="${CLIENT_IP:-10.0.0.2}"

# WireGuard overlay
WG_SERVER="${WG_SERVER:-wg-server}"
WG_CLIENT="${WG_CLIENT:-wg-client}"
WG_SERVER_IP="${WG_SERVER_IP:-10.10.10.1/32}"
WG_CLIENT_IP="${WG_CLIENT_IP:-10.10.10.2/32}"
WG_SERVER_IP6="${WG_SERVER_IP6:-fd00::1/64}"
WG_CLIENT_IP6="${WG_CLIENT_IP6:-fd00::2/64}"
WG_PORT="${WG_PORT:-51820}"

WIREGUARD_GO="${WIREGUARD_GO:-./wireguard-go}"
WG_LOG="${WG_LOG:-debug}"

# SCION + Bootstrap
SCION_DIR="${SCION_DIR:-../scion}"
TOPO_FILE="${TOPO_FILE:-topology/tiny.topo}" # relative to SCION_DIR
RUN_LOG="${RUN_LOG:-/tmp/scion_run.log}"

BOOTSTRAP_PY="${BOOTSTRAP_PY:-./bootstrap-server.py}"
BOOTSTRAP_BIND="${BOOTSTRAP_BIND:-10.0.0.1}"
BOOTSTRAP_PORT="${BOOTSTRAP_PORT:-8042}"
BOOTSTRAP_URL="http://${BOOTSTRAP_BIND}:${BOOTSTRAP_PORT}"

# Which AS directory to serve for endhost bootstrap (must exist under SCION_DIR/gen/)
BOOTSTRAP_AS="${BOOTSTRAP_AS:-ASff00_0_111}"
ASDIR="${ASDIR:-$SCION_DIR/gen/$BOOTSTRAP_AS}"

# Client local cache dir for downloaded topology+TRCs
SCION_CONFIG_DIR="${SCION_CONFIG_DIR:-/tmp/wg-scion}"

# SCION daemon address patching (expose sciond on WG overlay)
# Comma separated: "AS=PORT,AS=PORT"
# Using suffixes as they appear in gen/* (e.g. 0_111 -> matches gen/*0_111*/sd.toml)
EXPOSE="${EXPOSE:-0_111=30255,0_112=30256}"
SERVER_WG_IP="${SERVER_WG_IP:-10.10.10.1}"

# Keys (local files)
SERVER_PRIV_KEY="${SERVER_PRIV_KEY:-./server.key}"
SERVER_PUB_KEY="${SERVER_PUB_KEY:-./server.pub}"
CLIENT_PRIV_KEY="${CLIENT_PRIV_KEY:-./client.key}"
CLIENT_PUB_KEY="${CLIENT_PUB_KEY:-./client.pub}"

# =========================
# Helpers
# =========================
die(){ echo "Error: $*" >&2; exit 1; }
in_ns(){ sudo ip netns exec "$1" bash -lc "$2"; }

wait_for_socket() {
  local sock="$1"
  for i in {1..30}; do
    [[ -S "$sock" ]] && return 0
    sleep 0.2
  done
  die "UAPI socket not found: $sock"
}

dump_logs() {
  echo "---- Server wg log ----"
  in_ns "$SERVER_NS" "tail -n 200 /tmp/wg-server.log 2>/dev/null || true"
  echo "---- Client wg log ----"
  in_ns "$CLIENT_NS" "tail -n 200 /tmp/wg-client.log 2>/dev/null || true"
  echo "---- Bootstrap log ----"
  in_ns "$SERVER_NS" "tail -n 200 /tmp/bootstrap.log 2>/dev/null || true"
  echo "---- SCION run log ----"
  in_ns "$SERVER_NS" "tail -n 200 '$RUN_LOG' 2>/dev/null || true"
}

cleanup() {
  set +e
  echo "+ cleanup"
  in_ns "$SERVER_NS" "cd '$SCION_DIR' && ./scion.sh stop" 2>/dev/null || true
  in_ns "$SERVER_NS" "pkill -f bootstrap-server.py" 2>/dev/null || true
  in_ns "$SERVER_NS" "pkill wireguard-go" 2>/dev/null || true
  in_ns "$CLIENT_NS" "pkill wireguard-go" 2>/dev/null || true

  sudo ip netns del "$SERVER_NS" 2>/dev/null || true
  sudo ip netns del "$CLIENT_NS" 2>/dev/null || true
  sudo ip link del "$VETH1" 2>/dev/null || true

  rm -f "$SERVER_PRIV_KEY" "$SERVER_PUB_KEY" "$CLIENT_PRIV_KEY" "$CLIENT_PUB_KEY" 2>/dev/null || true
}
trap 'echo "!! failed"; dump_logs; exit 1' ERR

# =========================
# 1) Namespace setup (inline)
# =========================
ns_up() {
  echo "+ [1] Namespaces up"
  sudo ip netns add "$SERVER_NS" 2>/dev/null || true
  sudo ip netns add "$CLIENT_NS" 2>/dev/null || true

  sudo ip link add "$VETH1" type veth peer name "$VETH2" 2>/dev/null || true
  sudo ip link set "$VETH1" netns "$SERVER_NS"
  sudo ip link set "$VETH2" netns "$CLIENT_NS"

  in_ns "$SERVER_NS" "ip addr add '$SERVER_IP_CIDR' dev '$VETH1' 2>/dev/null || true"
  in_ns "$CLIENT_NS" "ip addr add '$CLIENT_IP_CIDR' dev '$VETH2' 2>/dev/null || true"

  in_ns "$SERVER_NS" "ip link set '$VETH1' up; ip link set lo up"
  in_ns "$CLIENT_NS" "ip link set '$VETH2' up; ip link set lo up"

  # simple default routes (optional but matches your earlier scripts)
  in_ns "$CLIENT_NS" "ip route add default via '$SERVER_IP' dev '$VETH2' 2>/dev/null || true"
  in_ns "$SERVER_NS" "ip route add default via '$CLIENT_IP' dev '$VETH1' 2>/dev/null || true"

  echo "+ [1] Underlay test"
  in_ns "$CLIENT_NS" "ping -c 1 '$SERVER_IP' >/dev/null"
  echo "  OK"
}

setup_tun() {
  # /dev/net/tun is not automatically present inside netns
  for ns in "$SERVER_NS" "$CLIENT_NS"; do
    in_ns "$ns" '
      mkdir -p /dev/net
      [[ -c /dev/net/tun ]] || mknod /dev/net/tun c 10 200
      chmod 600 /dev/net/tun
    '
  done
}

# =========================
# 2) SCION generate + patch + run
# =========================
sd_toml_for_as() {
  local as_suffix="$1"
  in_ns "$SERVER_NS" "cd '$SCION_DIR' && ls -d gen/*${as_suffix}*/sd.toml 2>/dev/null | head -n1 || true"
}

patch_as() {
  local as_suffix="$1" port="$2"
  local sd
  sd="$(sd_toml_for_as "$as_suffix")"
  [[ -n "${sd:-}" ]] || die "sd.toml for AS suffix '$as_suffix' not found (expected gen/*${as_suffix}*/sd.toml)"
  echo "+ [scion] Patch AS suffix=$as_suffix sciond address -> ${SERVER_WG_IP}:${port}"
  in_ns "$SERVER_NS" "
    cd '$SCION_DIR'
    sed -i -E \"s|^address *= *\\\".*\\\"|address = \\\"${SERVER_WG_IP}:${port}\\\"|\" '$sd'
    grep -n '^address' '$sd'
    grep -q '^address = \"${SERVER_WG_IP}:${port}\"' '$sd'
  "
}

start_scion() {
  echo "+ [2] SCION topology generate (Server ns)"
  in_ns "$SERVER_NS" "cd '$SCION_DIR' && ./scion.sh topology -c '$TOPO_FILE'"

  echo "+ [2] Patch sciond addresses for exposed ASes"
  IFS=',' read -ra pairs <<< "$EXPOSE"
  for p in "${pairs[@]}"; do
    p="$(echo "$p" | xargs)"
    [[ -n "$p" ]] || continue
    [[ "$p" == *"="* ]] || die "Bad EXPOSE entry '$p' (expected AS_SUFFIX=PORT)"
    local as_suffix="${p%%=*}"
    local port="${p#*=}"
    [[ "$port" =~ ^[0-9]+$ ]] || die "Bad port in EXPOSE '$p'"
    patch_as "$as_suffix" "$port"
  done

  echo "+ [2] Start SCION (Server ns) -> $RUN_LOG"
  in_ns "$SERVER_NS" "cd '$SCION_DIR' && (./scion.sh run > '$RUN_LOG' 2>&1 || true) &"
  sleep 3

  echo "+ [2] Quick SCION process check"
  in_ns "$SERVER_NS" "ps aux | grep -E 'sciond|dispatcher|control|router' | grep -v grep >/dev/null" || die "No SCION processes found"
}

# =========================
# 3) Bootstrap server (underlay)
# =========================
start_bootstrap() {
  echo "+ [3] Start Bootstrap server in Server ns (underlay: ${BOOTSTRAP_URL})"
  [[ -d "$ASDIR" ]] || die "ASDIR not found: $ASDIR (did topology generate?)"
  in_ns "$SERVER_NS" "python3 '$BOOTSTRAP_PY' '$ASDIR' '$BOOTSTRAP_BIND' '$BOOTSTRAP_PORT' > /tmp/bootstrap.log 2>&1 &"
  sleep 1

  echo "+ [4] Verify bootstrap reachable from Client"
  in_ns "$CLIENT_NS" "curl -sf '${BOOTSTRAP_URL}/topology' >/dev/null"
  in_ns "$CLIENT_NS" "curl -sf '${BOOTSTRAP_URL}/trcs' >/dev/null"
  echo "  OK"
}

# =========================
# 4) WireGuard (inline wg_tunnel.sh logic)
# =========================
generate_keys() {
  echo "+ [wg] Generating keys"
  rm -f "$SERVER_PRIV_KEY" "$SERVER_PUB_KEY" "$CLIENT_PRIV_KEY" "$CLIENT_PUB_KEY" || true
  wg genkey | tee "$SERVER_PRIV_KEY" | wg pubkey > "$SERVER_PUB_KEY"
  wg genkey | tee "$CLIENT_PRIV_KEY" | wg pubkey > "$CLIENT_PUB_KEY"
}

start_wireguard_go() {
  echo "+ [wg] Starting wireguard-go in namespaces"
  [[ -x "$WIREGUARD_GO" ]] || die "wireguard-go binary not found/executable: $WIREGUARD_GO"

  echo "+ [wg] Killing leftovers"
  sudo pkill wireguard-go 2>/dev/null || true
  in_ns "$SERVER_NS" "pkill wireguard-go 2>/dev/null || true"
  in_ns "$CLIENT_NS" "pkill wireguard-go 2>/dev/null || true"

  # Server (no bootstrap env needed)
  in_ns "$SERVER_NS" "
    export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
    export LOG_LEVEL=$WG_LOG
    '$WIREGUARD_GO' --foreground '$WG_SERVER' > /tmp/wg-server.log 2>&1
  " &
  sleep 3

  # Client (WITH bootstrap env)
  in_ns "$CLIENT_NS" "
    export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
    export LOG_LEVEL=$WG_LOG
    export SCION_BOOTSTRAP_URL='${BOOTSTRAP_URL}'
    export SCION_CONFIG_DIR='${SCION_CONFIG_DIR}'
    '$WIREGUARD_GO' --foreground '$WG_CLIENT' > /tmp/wg-client.log 2>&1
  " &
  sleep 3
}

configure_interfaces() {
  echo "+ [wg] Assigning tunnel IPs and bringing up interfaces"

  in_ns "$SERVER_NS" "ip addr add '$WG_SERVER_IP' dev '$WG_SERVER' 2>/dev/null || true"
  in_ns "$SERVER_NS" "ip addr add '$WG_SERVER_IP6' dev '$WG_SERVER' 2>/dev/null || true"
  in_ns "$SERVER_NS" "ip link set '$WG_SERVER' up"
  in_ns "$SERVER_NS" "ip -6 route add fd00::/64 dev '$WG_SERVER' 2>/dev/null || true"

  in_ns "$CLIENT_NS" "ip addr add '$WG_CLIENT_IP' dev '$WG_CLIENT' 2>/dev/null || true"
  in_ns "$CLIENT_NS" "ip addr add '$WG_CLIENT_IP6' dev '$WG_CLIENT' 2>/dev/null || true"
  in_ns "$CLIENT_NS" "ip link set '$WG_CLIENT' up"
  in_ns "$CLIENT_NS" "ip -6 route add fd00::/64 dev '$WG_CLIENT' 2>/dev/null || true"
}

configure_wireguard_uapi() {
  echo "+ [wg] Configuring WireGuard peers via UAPI (socat)"

  local UAPI_SOCKET_SERVER="/var/run/wireguard/${WG_SERVER}.sock"
  local UAPI_SOCKET_CLIENT="/var/run/wireguard/${WG_CLIENT}.sock"

  wait_for_socket "$UAPI_SOCKET_SERVER"
  wait_for_socket "$UAPI_SOCKET_CLIENT"

  local PRIVATE_KEY_HEX_SERVER PEER_PUBLIC_KEY_HEX_SERVER
  local PRIVATE_KEY_HEX_CLIENT PEER_PUBLIC_KEY_HEX_CLIENT

  PRIVATE_KEY_HEX_SERVER=$(base64 -d "$SERVER_PRIV_KEY" | xxd -p -c 256)
  PEER_PUBLIC_KEY_HEX_SERVER=$(base64 -d "$CLIENT_PUB_KEY" | xxd -p -c 256)

  PRIVATE_KEY_HEX_CLIENT=$(base64 -d "$CLIENT_PRIV_KEY" | xxd -p -c 256)
  PEER_PUBLIC_KEY_HEX_CLIENT=$(base64 -d "$SERVER_PUB_KEY" | xxd -p -c 256)

  echo "+ [wg] Server private key + listen"
  cat <<EOF | sudo socat - UNIX-CONNECT:"$UAPI_SOCKET_SERVER"
set=1
private_key=$PRIVATE_KEY_HEX_SERVER
listen_port=$WG_PORT
EOF

  echo "+ [wg] Server peer"
  cat <<EOF | sudo socat - UNIX-CONNECT:"$UAPI_SOCKET_SERVER"
set=1
public_key=$PEER_PUBLIC_KEY_HEX_SERVER
allowed_ip=$WG_CLIENT_IP
allowed_ip=$WG_CLIENT_IP6
endpoint=${CLIENT_IP}:${WG_PORT}
persistent_keepalive_interval=25
EOF

  echo "+ [wg] Client private key + listen"
  cat <<EOF | sudo socat - UNIX-CONNECT:"$UAPI_SOCKET_CLIENT"
set=1
private_key=$PRIVATE_KEY_HEX_CLIENT
listen_port=$WG_PORT
EOF

  echo "+ [wg] Client peer"
  cat <<EOF | sudo socat - UNIX-CONNECT:"$UAPI_SOCKET_CLIENT"
set=1
public_key=$PEER_PUBLIC_KEY_HEX_CLIENT
allowed_ip=$WG_SERVER_IP
allowed_ip=$WG_SERVER_IP6
endpoint=${SERVER_IP}:${WG_PORT}
persistent_keepalive_interval=25
EOF
}

wg_smoke_tests() {
  echo "+ [wg] Smoke test overlay"
  in_ns "$CLIENT_NS" "ping -c 2 10.10.10.1 >/dev/null || true"
  in_ns "$SERVER_NS" "wg show 2>/dev/null || true"
  in_ns "$CLIENT_NS" "wg show 2>/dev/null || true"
}

# =========================
# Main
# =========================
cmd_up() {
  ns_up
  setup_tun

  # SCION first (so ASDIR exists), then bootstrap server (underlay)
  start_scion
  start_bootstrap

  # WireGuard (client will bootstrap during wg-go startup via env)
  generate_keys
  start_wireguard_go
  configure_interfaces
  configure_wireguard_uapi
  wg_smoke_tests

  echo
  echo "=== DONE ==="
  echo "Bootstrap URL: $BOOTSTRAP_URL"
  echo "ASDIR served:  $ASDIR"
  echo
  echo "Client cache:"
  echo "  sudo ip netns exec $CLIENT_NS ls -la $SCION_CONFIG_DIR $SCION_CONFIG_DIR/certs"
  echo
  echo "Logs:"
  echo "  sudo ip netns exec $SERVER_NS tail -n 200 /tmp/bootstrap.log"
  echo "  sudo ip netns exec $SERVER_NS tail -n 200 $RUN_LOG"
  echo "  sudo ip netns exec $SERVER_NS tail -n 200 /tmp/wg-server.log"
  echo "  sudo ip netns exec $CLIENT_NS tail -n 200 /tmp/wg-client.log"
}

cmd_down() {
  cleanup
  echo "+ done"
}

case "${1:-}" in
  up) cmd_up ;;
  down) cmd_down ;;
  *)
    echo "Usage: $0 {up|down}"
    echo "Useful env:"
    echo "  SCION_DIR=../scion TOPO_FILE=topology/tiny.topo"
    echo "  BOOTSTRAP_AS=ASff00_0_111 BOOTSTRAP_BIND=10.0.0.1 BOOTSTRAP_PORT=8042"
    echo "  EXPOSE='0_111=30255,0_112=30256' SERVER_WG_IP=10.10.10.1"
    exit 1
    ;;
esac
