#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Paths: everything is derived from the cloned repository.
# Expected layout: <repo>/testenvironment/config.sh
# -----------------------------------------------------------------------------
SCRIPT_DIR_CONFIG="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export TESTENV_DIR="${TESTENV_DIR:-$SCRIPT_DIR_CONFIG}"
export REPO_ROOT="${REPO_ROOT:-$(cd "$TESTENV_DIR/.." && pwd)}"
export RUNTIME_DIR="${RUNTIME_DIR:-$TESTENV_DIR/.runtime}"
export DEPS_DIR="${DEPS_DIR:-$TESTENV_DIR/.deps}"
export LOGS_DIR="${LOGS_DIR:-$RUNTIME_DIR/logs}"
export LOG_DIR="$LOGS_DIR"
export SCION_BUILD_LOG="${SCION_BUILD_LOG:-$LOGS_DIR/scion-build.log}"
export KEYS_DIR="${KEYS_DIR:-$RUNTIME_DIR/keys}"
export BIN_DIR="${BIN_DIR:-$RUNTIME_DIR/bin}"
export STATE_DIR="${STATE_DIR:-$RUNTIME_DIR/state}"
export INSTALL_STATE_DIR="${INSTALL_STATE_DIR:-$TESTENV_DIR/.install-state}"
export APT_MANIFEST="${APT_MANIFEST:-$INSTALL_STATE_DIR/apt-installed-by-testenvironment.txt}"
export SCION_APT_SOURCE_MARKER="${SCION_APT_SOURCE_MARKER:-$INSTALL_STATE_DIR/scion-apt-source-created}"
export SCION_APT_KEY_MARKER="${SCION_APT_KEY_MARKER:-$INSTALL_STATE_DIR/scion-apt-key-created}"
export SCION_STATE_FILE="${SCION_STATE_FILE:-$INSTALL_STATE_DIR/scion-source.env}"
export GO_STATE_FILE="${GO_STATE_FILE:-$INSTALL_STATE_DIR/go-source.env}"
export SYSTEM_GO_STATE_FILE="${SYSTEM_GO_STATE_FILE:-$INSTALL_STATE_DIR/system-go.env}"
export SYSTEM_GO_MARKER="${SYSTEM_GO_MARKER:-$INSTALL_STATE_DIR/system-go-installed-by-testenvironment}"

# SCION source checkout. Prefer the exact commit encoded in this repository's
# github.com/scionproto/scion pseudo-version, so topology/runtime and translator
# use matching SCION code.
export SCION_REPO_URL="${SCION_REPO_URL:-https://github.com/scionproto/scion.git}"
_detected_scion_ref=""
if [[ -f "$REPO_ROOT/go.mod" ]]; then
    _scion_version="$(awk '$1=="github.com/scionproto/scion" {print $2; exit}' "$REPO_ROOT/go.mod" 2>/dev/null || true)"
    _candidate_ref="${_scion_version##*-}"
    [[ "$_candidate_ref" =~ ^[0-9a-fA-F]{7,40}$ ]] && _detected_scion_ref="$_candidate_ref"
fi
export SCION_REF="${SCION_REF:-${_detected_scion_ref:-cce7754b652c}}"
export SCION_MANAGED_DIR="${SCION_MANAGED_DIR:-$DEPS_DIR/scion}"
# Pinned Python tooling used by SCION's topology/supervisor scripts. Keeping
# these packages under .deps avoids modifying the system Python environment.
export SCION_PYTHON_DEPS_DIR="${SCION_PYTHON_DEPS_DIR:-$DEPS_DIR/scion-python}"
if [[ -d "$SCION_PYTHON_DEPS_DIR" ]]; then
    export PYTHONPATH="$SCION_PYTHON_DEPS_DIR${PYTHONPATH:+:$PYTHONPATH}"
fi

# SCION can either be managed by this test environment or supplied by the user.
# A persisted selection wins over the initial default on later script invocations.
_scion_dir_from_env="${SCION_DIR:-}"
_scion_source_from_env="${SCION_SOURCE:-}"
if [[ -f "$SCION_STATE_FILE" && ( -z "$_scion_source_from_env" || "$_scion_source_from_env" == "unconfigured" ) ]]; then
    # shellcheck disable=SC1090
    source "$SCION_STATE_FILE"
fi
if [[ -z "${SCION_DIR:-}" ]]; then
    export SCION_DIR="$SCION_MANAGED_DIR"
fi
if [[ -z "${SCION_SOURCE:-}" ]]; then
    if [[ -n "$_scion_dir_from_env" && "$_scion_dir_from_env" != "$SCION_MANAGED_DIR" ]]; then
        export SCION_SOURCE="external"
    elif [[ -d "$SCION_MANAGED_DIR/.git" ]]; then
        export SCION_SOURCE="managed"
    else
        export SCION_SOURCE="unconfigured"
    fi
fi
export SCION_TOPOLOGY="${SCION_TOPOLOGY:-$TESTENV_DIR/topology/scion-ring-3isd.topo}"

# Optional translator path policy. Reuse one from the repository/SCION checkout
# if present; otherwise the client is started without SCION_POLICY_FILE.
if [[ -z "${SCION_POLICY_FILE:-}" ]]; then
    for _p in "$TESTENV_DIR/policies/policy-v0.json" "$REPO_ROOT/policies/policy-v0.json" "$SCION_DIR/policies/policy-v0.json"; do
        if [[ -f "$_p" ]]; then SCION_POLICY_FILE="$_p"; break; fi
    done
    SCION_POLICY_FILE="${SCION_POLICY_FILE:-$TESTENV_DIR/policies/policy-v0.json}"
fi
export SCION_POLICY_FILE

# -----------------------------------------------------------------------------
# Namespaces
# -----------------------------------------------------------------------------
export SERVER_NS="${SERVER_NS:-Server}"
export CLIENT_NS="${CLIENT_NS:-Client}"
export SCITRA_NS="${SCITRA_NS:-ScitraServer}"

# Client <-> Server underlay for WireGuard.
export SERVER_VETH_IFACE="${SERVER_VETH_IFACE:-veth-server}"
export CLIENT_VETH_IFACE="${CLIENT_VETH_IFACE:-veth-client}"
export SERVER_VETH_IP="${SERVER_VETH_IP:-10.10.10.1/24}"
export CLIENT_VETH_IP="${CLIENT_VETH_IP:-10.10.10.2/24}"

# Server AS <-> Scitra end-host network.
export SCITRA_SERVER_IFACE="${SCITRA_SERVER_IFACE:-veth-as-scitra}"
export SCITRA_HOST_IFACE="${SCITRA_HOST_IFACE:-veth-scitra}"
export SCITRA_SUBNET="${SCITRA_SUBNET:-10.30.34.0/24}"
export SCITRA_HOST_IP_CIDR="${SCITRA_HOST_IP_CIDR:-10.30.34.100/24}"
export SCITRA_HOST_IP="${SCITRA_HOST_IP:-${SCITRA_HOST_IP_CIDR%%/*}}"
export SCITRA_DAEMON_IP="${SCITRA_DAEMON_IP:-10.30.34.254}"
export SCITRA_DAEMON_PORT="${SCITRA_DAEMON_PORT:-30255}"
export SCITRA_DAEMON_ADDR="${SCITRA_DAEMON_ADDR:-$SCITRA_DAEMON_IP:$SCITRA_DAEMON_PORT}"
export SCITRA_BR_FIRST_IP="${SCITRA_BR_FIRST_IP:-10.30.34.1}"

# -----------------------------------------------------------------------------
# SCION identities
# -----------------------------------------------------------------------------
export SOURCE_IA="${SOURCE_IA:-1-64512}"
export SOURCE_ASN="${SOURCE_ASN:-64512}"
export TARGET_IA="${TARGET_IA:-3-64534}"
export TARGET_ASN="${TARGET_ASN:-64534}"

# SCION control/data-plane convergence. After all services are RUNNING, the
# local multi-AS topology still needs time to originate, propagate and register
# path segments. Poll actively instead of failing on the first empty lookup.
export SCION_PATH_READY_TIMEOUT="${SCION_PATH_READY_TIMEOUT:-180}"
export SCION_PATH_READY_INTERVAL="${SCION_PATH_READY_INTERVAL:-5}"
export SCION_PATH_QUERY_TIMEOUT="${SCION_PATH_QUERY_TIMEOUT:-8}"
export SCION_PATH_STABLE_SUCCESSES="${SCION_PATH_STABLE_SUCCESSES:-2}"

# Compatibility with existing translator environment names.
export SCION_LOCAL_IA="${SCION_LOCAL_IA:-$SOURCE_ASN}"
export SCION_CONFIG_DIR="${SCION_CONFIG_DIR:-$SCION_DIR/gen/AS$SOURCE_ASN}"
export DEAMON_CONFIG_FILE="${DEAMON_CONFIG_FILE:-$SCION_CONFIG_DIR/sd.toml}"

# Source-AS addresses exposed through wg-server. 04-topo_change.sh may add more
# BR aliases dynamically and writes them to $STATE_DIR/topology-runtime.env.
export SOURCE_DAEMON_IP="${SOURCE_DAEMON_IP:-10.0.0.3}"
export SOURCE_DAEMON_ADDR="${SOURCE_DAEMON_ADDR:-$SOURCE_DAEMON_IP:30255}"
# Source Control/Discovery Service exposed through wg-server. The generated
# local topology normally uses a namespace-local 127/8 address (e.g.
# 127.0.0.44:31000). A bootstrapped translator in Client must instead receive
# a WireGuard-routable address.
export SOURCE_CONTROL_IP="${SOURCE_CONTROL_IP:-10.0.0.6}"
# The actual control-service port is discovered from the generated topology by
# tools/patch_topology.py and written to topology-runtime.env.
export SOURCE_CONTROL_PORT="${SOURCE_CONTROL_PORT:-31000}"
export SOURCE_CONTROL_ADDR="${SOURCE_CONTROL_ADDR:-$SOURCE_CONTROL_IP:$SOURCE_CONTROL_PORT}"
export SERVER_65413_sciond_addr="${SERVER_65413_sciond_addr:-$SOURCE_DAEMON_IP/8}"

# -----------------------------------------------------------------------------
# WireGuard
# -----------------------------------------------------------------------------
export WG_SERVER_IFACE="${WG_SERVER_IFACE:-wg-server}"
export WG_CLIENT_IFACE="${WG_CLIENT_IFACE:-wg-client}"
export WG_SERVER_IP="${WG_SERVER_IP:-10.0.0.1/24}"
export WG_CLIENT_IP="${WG_CLIENT_IP:-10.0.0.2/24}"
export WG_ENDPOINT="${WG_ENDPOINT:-${SERVER_VETH_IP%%/*}:51820}"

# A normal IPv6 source address for curl. It deliberately does not overlap the
# SCION-mapped fc00::/8 destination prefix.
export WG_CLIENT_IPV6="${WG_CLIENT_IPV6:-fc00:10fc::ffff:10.0.0.2/128}"

# Custom translator routing prefix. Scitra-TUN itself uses fc00::/8.
export WG_SCION_ROUTE_PREFIX="${WG_SCION_ROUTE_PREFIX:-fc00::/8}"

export SCION_UNDERLAY_PORT="${SCION_UNDERLAY_PORT:-30041}"
export SCION_LISTENER_PORT="$((SCION_UNDERLAY_PORT + 1))"
export SCION_ENABLED="${SCION_ENABLED:-true}"
export SCION_BOOTSTRAP_URL="${SCION_BOOTSTRAP_URL:-http://${WG_SERVER_IP%%/*}:8042}"

# -----------------------------------------------------------------------------
# Bootstrap server for the source AS / custom translator
# -----------------------------------------------------------------------------
export BOOTSTRAP_AS="${BOOTSTRAP_AS:-AS$SOURCE_ASN}"
export BOOTSTRAP_BIND="${BOOTSTRAP_BIND:-${WG_SERVER_IP%%/*}}"
export BOOTSTRAP_PORT="${BOOTSTRAP_PORT:-8042}"
export BOOTSTRAP_PY="${BOOTSTRAP_PY:-$TESTENV_DIR/tools/bootstrap_server.py}"

# -----------------------------------------------------------------------------
# Scitra / website
# -----------------------------------------------------------------------------
export SCITRA_PORT="${SCITRA_PORT:-8000}"
export PLAIN_WEBSITE_PORT="${PLAIN_WEBSITE_PORT:-8080}"
export SCITRA_TUN_IFACE="${SCITRA_TUN_IFACE:-scion}"
export WEBSITE_DIR="${WEBSITE_DIR:-$TESTENV_DIR/website}"
export SCION_WEBSITE_DIR="${SCION_WEBSITE_DIR:-$WEBSITE_DIR/scion}"
export PLAIN_WEBSITE_DIR="${PLAIN_WEBSITE_DIR:-$WEBSITE_DIR/ip}"
export WEBSITE_PID_FILE="${WEBSITE_PID_FILE:-$STATE_DIR/scion-website.pid}"
export PLAIN_WEBSITE_PID_FILE="${PLAIN_WEBSITE_PID_FILE:-$STATE_DIR/plain-website.pid}"
export SCITRA_PID_FILE="${SCITRA_PID_FILE:-$STATE_DIR/scitra-tun.pid}"
export WEBSITE_IP_FILE="${WEBSITE_IP_FILE:-$STATE_DIR/website-ip.txt}"

# Known-good source-side Scitra reference client. It is started in the Server
# namespace during setup, validates the complete SCION/TCP/target-Scitra path
# without our custom translator, and remains running for side-by-side debugging
# until 'down', 'clean', 'purge', or 'uninstall'.
export REFERENCE_SCITRA_IP="${REFERENCE_SCITRA_IP:-10.0.0.100}"
export REFERENCE_SCITRA_PID_FILE="${REFERENCE_SCITRA_PID_FILE:-$STATE_DIR/reference-scitra.pid}"
export REFERENCE_SCITRA_IP_FILE="${REFERENCE_SCITRA_IP_FILE:-$STATE_DIR/reference-scitra-ip.txt}"

# -----------------------------------------------------------------------------
# Dependency management
# -----------------------------------------------------------------------------
# Minimum Go version required by the pinned SCION checkout. If the system Go is
# missing or too old, the user can choose between a test-local Go under .deps/go,
# a system-wide Go under /usr/local/go, or another existing Go installation.
export GO_VERSION="${GO_VERSION:-1.24.2}"
export MANAGED_GO_VERSION="${MANAGED_GO_VERSION:-1.24.12}"
export MANAGED_GO_DIR="${MANAGED_GO_DIR:-$DEPS_DIR/go}"
export SYSTEM_GO_DIR="${SYSTEM_GO_DIR:-/usr/local/go}"
export SYSTEM_GO_PROFILE="${SYSTEM_GO_PROFILE:-/etc/profile.d/go-testenvironment.sh}"
_go_bin_from_env="${GO_BIN:-}"
_go_source_from_env="${GO_SOURCE:-}"
if [[ -f "$GO_STATE_FILE" && -z "$_go_bin_from_env" && -z "$_go_source_from_env" ]]; then
    # shellcheck disable=SC1090
    source "$GO_STATE_FILE"
fi
if [[ -z "${GO_BIN:-}" ]]; then
    export GO_BIN="$(command -v go 2>/dev/null || true)"
fi
if [[ -z "${GO_SOURCE:-}" ]]; then
    if [[ -n "$_go_bin_from_env" ]]; then
        export GO_SOURCE="external"
    elif [[ "$GO_BIN" == "$MANAGED_GO_DIR/bin/go" ]]; then
        export GO_SOURCE="managed"
    elif [[ "$GO_BIN" == "$SYSTEM_GO_DIR/bin/go" && -f "$SYSTEM_GO_MARKER" ]]; then
        export GO_SOURCE="system-managed"
    elif [[ -n "$GO_BIN" ]]; then
        export GO_SOURCE="system"
    else
        export GO_SOURCE="unconfigured"
    fi
fi

# Go module/build caches used by this testenvironment are isolated under .deps,
# so purge/uninstall can remove them without touching ~/go/pkg/mod or the user's
# normal ~/.cache/go-build.
export GO_MOD_CACHE="${GO_MOD_CACHE:-$DEPS_DIR/go-mod-cache}"
export GO_BUILD_CACHE="${GO_BUILD_CACHE:-$DEPS_DIR/go-build-cache}"
export AUTO_INSTALL_DEPS="${AUTO_INSTALL_DEPS:-1}"

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
export LOG_LEVEL="${LOG_LEVEL:-verbose}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_debug()   { [[ "$LOG_LEVEL" == debug ]] && echo "[DEBUG] $*" || true; }
log_step()    { echo; echo -e "${GREEN}====== STEP: $* ======${NC}"; }

check_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        log_error "This script must be run as root (sudo ./testenvironment.bash)"
        exit 1
    fi
}

check_command() {
    command -v "$1" >/dev/null 2>&1 || { log_error "Required command not found: $1"; return 1; }
}

wait_for() {
    local timeout="$1" description="$2" cmd="$3"
    for _ in $(seq 1 "$timeout"); do
        if eval "$cmd" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    log_error "Timeout waiting for: $description"
    return 1
}

create_directories() {
    mkdir -p "$RUNTIME_DIR" "$LOGS_DIR" "$KEYS_DIR" "$BIN_DIR" "$STATE_DIR" "$DEPS_DIR" "$INSTALL_STATE_DIR"
}

is_namespace_running() {
    ip netns list 2>/dev/null | grep -qE "^${1}( |$)"
}

runtime_env_file() { echo "$STATE_DIR/topology-runtime.env"; }

load_runtime_env() {
    local f; f="$(runtime_env_file)"
    [[ -f "$f" ]] && source "$f" || true
}

print_config() {
    cat <<CFG
========================================
 SCION-WireGuard-Scitra Test Environment
========================================
Repository:       $REPO_ROOT
Test environment: $TESTENV_DIR
Runtime:          $RUNTIME_DIR
SCION checkout:   $SCION_DIR
SCION source:     $SCION_SOURCE
Expected ref:     $SCION_REF
Topology:         $SCION_TOPOLOGY
Go source:        ${GO_SOURCE:-unconfigured}
Go binary:        ${GO_BIN:-not configured}

Namespaces:
  Client:         $CLIENT_NS
  SCION:          $SERVER_NS
  Scitra:         $SCITRA_NS

SCION:
  Source IA:      $SOURCE_IA
  Source control: $SOURCE_CONTROL_ADDR (patched from generated 127/8 to wg-server)
  Target IA:      $TARGET_IA
  Scitra host:    $SCITRA_HOST_IP
  Scitra daemon:  $SCITRA_DAEMON_ADDR
  SCION website:  TCP/$SCITRA_PORT
  Plain IP site:   http://$SCITRA_HOST_IP:$PLAIN_WEBSITE_PORT/
  Path readiness:  poll every ${SCION_PATH_READY_INTERVAL}s, max ${SCION_PATH_READY_TIMEOUT}s, ${SCION_PATH_STABLE_SUCCESSES} stable alive checks
CFG
}
