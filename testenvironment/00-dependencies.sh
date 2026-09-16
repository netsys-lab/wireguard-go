#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
check_root

log_step "Dependencies / Pre-flight check"

# Check standard host packages
for cmd in ip wg socat jq python3 tcpdump nc curl git supervisorctl supervisord; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_error "Missing prerequisite: $cmd"
        log_error "Please install it. See README.md for the required packages."
        exit 1
    fi
done

# Check Go
if ! command -v go >/dev/null 2>&1; then
    log_error "Missing prerequisite: go"
    log_error "Go >= $GO_VERSION is required. See README.md."
    exit 1
fi

GO_CURRENT=$(go version | awk '{print $3}' | sed 's/^go//')
log_info "Detected Go version: $GO_CURRENT"

# Check SCION
if [[ -z "${SCION_DIR:-}" ]]; then
    log_error "SCION_DIR environment variable is not set."
    log_error "Please set it to your SCION source checkout. Example: sudo SCION_DIR=/path/to/scion ./testenvironment.bash"
    exit 1
fi

if [[ ! -d "$SCION_DIR" || ! -f "$SCION_DIR/tools/topogen.py" ]]; then
    log_error "Invalid SCION_DIR: $SCION_DIR"
    log_error "The directory must contain tools/topogen.py"
    log_error "If your SCION checkout is located elsewhere, run: sudo SCION_DIR=/path/to/scion ./testenvironment.bash up"
    exit 1
fi

# Check for compiled SCION binaries
for bin in router control dispatcher daemon scion scion-pki; do
    if [[ ! -x "$SCION_DIR/bin/$bin" ]]; then
        log_error "Missing compiled SCION binary: $SCION_DIR/bin/$bin"
        log_error "Please build SCION binaries as described in README.md."
        exit 1
    fi
done
export SCION_DIR

# Check Python dependencies for SCION topogen
if ! python3 -c 'import toml, yaml, plumbum, supervisor, supervisorwildcards, six' 2>/dev/null; then
    log_error "Missing Python dependencies for SCION."
    log_error "Please ensure you have installed the requirements for topogen.py (e.g. pip install -r env/pip3/requirements.txt)."
    exit 1
fi

# Check Scitra-TUN
for cmd in scitra-tun scion2ip; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_error "Missing prerequisite: $cmd"
        log_error "Please install the scitra-tun packages. See README.md."
        exit 1
    fi
done

# Setup needed cache dirs
mkdir -p "$GO_MOD_CACHE" "$GO_BUILD_CACHE" "$RUNTIME_DIR" "$LOGS_DIR" "$BIN_DIR" "$KEYS_DIR" "$STATE_DIR"
if [[ "${SUDO_USER:-root}" != root ]]; then
    chown -R "${SUDO_USER:-root}:$(id -gn "${SUDO_USER:-root}" 2>/dev/null || echo root)" "$GO_MOD_CACHE" "$GO_BUILD_CACHE" "$RUNTIME_DIR"
fi

log_success "All prerequisites met!"
