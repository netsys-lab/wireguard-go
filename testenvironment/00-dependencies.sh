#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
check_root

log_step "Dependencies"

RUN_USER="${SUDO_USER:-root}"
RUN_GROUP="$(id -gn "$RUN_USER" 2>/dev/null || echo root)"
RUN_HOME="$(getent passwd "$RUN_USER" 2>/dev/null | cut -d: -f6)"
RUN_HOME="${RUN_HOME:-/root}"

run_as_user() {
    if [[ "$RUN_USER" == root ]]; then
        "$@"
    else
        sudo -u "$RUN_USER" -H "$@"
    fi
}

version_ge() {
    [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]
}

package_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q '^install ok installed$'
}

record_new_package() {
    mkdir -p "$INSTALL_STATE_DIR"
    touch "$APT_MANIFEST"
    grep -qxF "$1" "$APT_MANIFEST" 2>/dev/null || echo "$1" >> "$APT_MANIFEST"
}

install_packages_tracked() {
    local pkg
    local missing=()
    for pkg in "$@"; do
        if ! package_installed "$pkg"; then
            missing+=("$pkg")
        fi
    done

    if ((${#missing[@]} == 0)); then
        return 0
    fi

    apt-get install -y --no-install-recommends "${missing[@]}"
    for pkg in "${missing[@]}"; do
        package_installed "$pkg" && record_new_package "$pkg"
    done
}

install_host_packages() {
    [[ "$AUTO_INSTALL_DEPS" == 1 ]] || return 0

    [[ -f /etc/os-release ]] || { log_error "Cannot detect Linux distribution"; return 1; }
    . /etc/os-release
    [[ "${ID:-}" == ubuntu ]] || {
        log_error "Automatic package installation currently supports Ubuntu only (detected: ${ID:-unknown})"
        return 1
    }

    # Deliberately small: only commands directly used by the scripts or by
    # SCION's local supervisor/topology tooling.
    local packages=(
        ca-certificates
        curl
        git
        iproute2
        iputils-ping
        wireguard-tools
        socat
        xxd
        jq
        python3
        python3-pip
        python3-yaml
        python3-plumbum
        supervisor
        procps
        tar
        gzip
    )

    if [[ "${INSTALL_DEBUG_TOOLS:-0}" == 1 ]]; then
        packages+=(tcpdump netcat-openbsd)
    fi

    log_info "Refreshing APT package lists..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    log_info "Installing only missing required host packages..."
    install_packages_tracked "${packages[@]}"
    log_success "Required host packages are ready"
}

persist_go_selection() {
    mkdir -p "$INSTALL_STATE_DIR"
    {
        printf 'GO_SOURCE=%q\n' "$GO_SOURCE"
        printf 'GO_BIN=%q\n' "$GO_BIN"
    } > "$GO_STATE_FILE"
}

local_go_version() {
    local bin="$1"
    [[ -x "$bin" ]] || return 1
    GOTOOLCHAIN=local "$bin" version 2>/dev/null | awk '{print $3}' | sed 's/^go//'
}

validate_go_binary() {
    local bin="$1" current
    [[ -x "$bin" ]] || { log_error "Go binary is not executable: $bin"; return 1; }
    current="$(local_go_version "$bin" || true)"
    [[ -n "$current" ]] || { log_error "Could not determine Go version from: $bin"; return 1; }
    if ! version_ge "$current" "$GO_VERSION"; then
        log_error "Go $current at $bin is too old; Go >= $GO_VERSION is required."
        return 1
    fi
    return 0
}

normalize_go_path() {
    local input="$1"
    if [[ "$input" == "~" ]]; then
        input="$RUN_HOME"
    elif [[ "$input" == "~/"* ]]; then
        input="$RUN_HOME/${input:2}"
    fi

    if [[ -f "$input" ]]; then
        readlink -f "$input"
    elif [[ -x "$input/bin/go" ]]; then
        readlink -f "$input/bin/go"
    elif [[ -x "$input/go" ]]; then
        readlink -f "$input/go"
    else
        printf '%s\n' "$input"
    fi
}

managed_go_download_info() {
    local arch
    case "$(uname -m)" in
        x86_64|amd64)
            arch="amd64"
            GO_ARCHIVE_SHA256="bddf8e653c82429aea7aec2520774e79925d4bb929fe20e67ecc00dd5af44c50"
            ;;
        aarch64|arm64)
            arch="arm64"
            GO_ARCHIVE_SHA256="4e02e2979e53b40f3666bba9f7e5ea0b99ea5156e0824b343fd054742c25498d"
            ;;
        *)
            return 1
            ;;
    esac
    GO_ARCHIVE_NAME="go${MANAGED_GO_VERSION}.linux-${arch}.tar.gz"
    GO_ARCHIVE_URL="https://go.dev/dl/${GO_ARCHIVE_NAME}"
    export GO_ARCHIVE_NAME GO_ARCHIVE_URL GO_ARCHIVE_SHA256
}

download_go_archive() {
    managed_go_download_info || {
        log_error "Automatic Go installation is currently supported only on Linux amd64/arm64."
        return 1
    }
    local tmp
    tmp="$(mktemp --suffix=.tar.gz)"
    if ! curl -fL --retry 3 --progress-bar "$GO_ARCHIVE_URL" -o "$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    if ! echo "$GO_ARCHIVE_SHA256  $tmp" | sha256sum -c - >/dev/null; then
        rm -f "$tmp"
        log_error "Checksum verification failed for $GO_ARCHIVE_NAME"
        return 1
    fi
    printf '%s\n' "$tmp"
}

persist_system_go_state() {
    mkdir -p "$INSTALL_STATE_DIR"
    {
        printf 'SYSTEM_GO_BACKUP_DIR=%q\n' "${SYSTEM_GO_BACKUP_DIR:-}"
        printf 'SYSTEM_GO_BIN_BACKUP=%q\n' "${SYSTEM_GO_BIN_BACKUP:-}"
        printf 'SYSTEM_GOFMT_BIN_BACKUP=%q\n' "${SYSTEM_GOFMT_BIN_BACKUP:-}"
    } > "$SYSTEM_GO_STATE_FILE"
    touch "$SYSTEM_GO_MARKER"
}

install_system_go() {
    log_warn "You selected a SYSTEM-WIDE Go update."
    log_info "Go $MANAGED_GO_VERSION will be installed under $SYSTEM_GO_DIR"
    log_info "The testenvironment will use it immediately, and /usr/local/bin/go will point to it."
    log_info "The previous /usr/local Go installation/symlinks are preserved so 'uninstall' can restore them."

    local tmp stamp
    tmp="$(download_go_archive)" || return 1
    stamp="$(date +%Y%m%d%H%M%S)"
    mkdir -p "$INSTALL_STATE_DIR"

    SYSTEM_GO_BACKUP_DIR=""
    SYSTEM_GO_BIN_BACKUP=""
    SYSTEM_GOFMT_BIN_BACKUP=""

    if [[ -e "$SYSTEM_GO_DIR" && ! -f "$SYSTEM_GO_MARKER" ]]; then
        SYSTEM_GO_BACKUP_DIR="${SYSTEM_GO_DIR}.testenvironment-backup-${stamp}"
        log_info "Preserving existing $SYSTEM_GO_DIR as $SYSTEM_GO_BACKUP_DIR"
        mv "$SYSTEM_GO_DIR" "$SYSTEM_GO_BACKUP_DIR"
    else
        rm -rf "$SYSTEM_GO_DIR"
    fi

    if [[ -e /usr/local/bin/go || -L /usr/local/bin/go ]]; then
        if [[ "$(readlink -f /usr/local/bin/go 2>/dev/null || true)" != "$SYSTEM_GO_DIR/bin/go" ]]; then
            SYSTEM_GO_BIN_BACKUP="/usr/local/bin/go.testenvironment-backup-${stamp}"
            mv /usr/local/bin/go "$SYSTEM_GO_BIN_BACKUP"
        else
            rm -f /usr/local/bin/go
        fi
    fi
    if [[ -e /usr/local/bin/gofmt || -L /usr/local/bin/gofmt ]]; then
        if [[ "$(readlink -f /usr/local/bin/gofmt 2>/dev/null || true)" != "$SYSTEM_GO_DIR/bin/gofmt" ]]; then
            SYSTEM_GOFMT_BIN_BACKUP="/usr/local/bin/gofmt.testenvironment-backup-${stamp}"
            mv /usr/local/bin/gofmt "$SYSTEM_GOFMT_BIN_BACKUP"
        else
            rm -f /usr/local/bin/gofmt
        fi
    fi

    if ! tar -C /usr/local -xzf "$tmp"; then
        rm -f "$tmp"
        log_error "Failed to extract Go into /usr/local"
        return 1
    fi
    rm -f "$tmp"

    ln -sfn "$SYSTEM_GO_DIR/bin/go" /usr/local/bin/go
    ln -sfn "$SYSTEM_GO_DIR/bin/gofmt" /usr/local/bin/gofmt
    cat > "$SYSTEM_GO_PROFILE" <<EOF
# Added by SCION/WireGuard testenvironment.
export PATH="$SYSTEM_GO_DIR/bin:\$PATH"
EOF

    GO_SOURCE="system-managed"
    GO_BIN="$SYSTEM_GO_DIR/bin/go"
    export GO_SOURCE GO_BIN
    validate_go_binary "$GO_BIN"
    persist_system_go_state
    persist_go_selection
    log_success "System-wide Go $(local_go_version "$GO_BIN") ready at $GO_BIN"
}

prepare_go_cache_dirs() {
    mkdir -p "$GO_MOD_CACHE" "$GO_BUILD_CACHE" "$RUNTIME_DIR" "$LOGS_DIR" "$BIN_DIR" "$KEYS_DIR" "$STATE_DIR"
    if [[ "$RUN_USER" != root ]]; then
        chown -R "$RUN_USER:$RUN_GROUP" "$GO_MOD_CACHE" "$GO_BUILD_CACHE" "$RUNTIME_DIR"
    fi
}

install_managed_go() {
    log_info "Installing Go $MANAGED_GO_VERSION only for this testenvironment."
    log_info "Target: $MANAGED_GO_DIR"
    log_info "Your system Go installation will NOT be modified."

    mkdir -p "$DEPS_DIR"
    local tmp
    tmp="$(download_go_archive)" || return 1

    rm -rf "$MANAGED_GO_DIR"
    if ! tar -C "$DEPS_DIR" -xzf "$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    rm -f "$tmp"
    [[ -x "$MANAGED_GO_DIR/bin/go" ]] || {
        log_error "Managed Go extraction did not create $MANAGED_GO_DIR/bin/go"
        return 1
    }
    if [[ "$RUN_USER" != root ]]; then
        chown -R "$RUN_USER:$RUN_GROUP" "$MANAGED_GO_DIR"
    fi

    GO_SOURCE="managed"
    GO_BIN="$MANAGED_GO_DIR/bin/go"
    export GO_SOURCE GO_BIN
    validate_go_binary "$GO_BIN"
    persist_go_selection
    log_success "Managed Go $(local_go_version "$GO_BIN") ready at $GO_BIN"
}

ask_for_existing_go() {
    echo
    echo "Please provide a path to an existing Go installation with Go >= $GO_VERSION."
    echo "You can paste the Go root directory, its bin directory, or the go binary itself."
    echo
    echo "Examples:"
    echo "  /usr/local/go"
    echo "  /usr/local/go/bin"
    echo "  /usr/local/go/bin/go"
    echo "  /home/$RUN_USER/tools/go/bin/go"
    echo

    local input candidate
    while true; do
        read -r -p "Path to existing Go: " input
        candidate="$(normalize_go_path "$input")"
        if validate_go_binary "$candidate"; then
            GO_SOURCE="external"
            GO_BIN="$candidate"
            export GO_SOURCE GO_BIN
            persist_go_selection
            log_success "Using external Go $(local_go_version "$GO_BIN") at $GO_BIN"
            return 0
        fi
        echo
        log_warn "That path does not provide a compatible Go toolchain. Please try again."
    done
}

ensure_go() {
    # An explicit GO_INSTALL_MODE overrides a persisted selection. This is useful
    # when a developer wants to switch from test-local Go to system-wide Go (or vice versa).
    if [[ -n "${GO_INSTALL_MODE:-}" ]]; then
        case "$GO_INSTALL_MODE" in
            managed|local|testenvironment)
                if [[ -x "$MANAGED_GO_DIR/bin/go" ]] && validate_go_binary "$MANAGED_GO_DIR/bin/go" >/dev/null 2>&1; then
                    GO_SOURCE="managed"
                    GO_BIN="$MANAGED_GO_DIR/bin/go"
                    export GO_SOURCE GO_BIN
                    persist_go_selection
                    log_success "Using managed Go $(local_go_version "$GO_BIN") at $GO_BIN"
                else
                    install_managed_go
                fi
                return 0
                ;;
            system|system-managed)
                # Explicit system mode means make a compatible Go available system-wide.
                if [[ -x "$SYSTEM_GO_DIR/bin/go" ]] && validate_go_binary "$SYSTEM_GO_DIR/bin/go" >/dev/null 2>&1 && [[ -f "$SYSTEM_GO_MARKER" ]]; then
                    GO_SOURCE="system-managed"
                    GO_BIN="$SYSTEM_GO_DIR/bin/go"
                    export GO_SOURCE GO_BIN
                    persist_go_selection
                    log_success "Using testenvironment-managed system Go $(local_go_version "$GO_BIN") at $GO_BIN"
                else
                    install_system_go
                fi
                return 0
                ;;
            external)
                if [[ -n "${GO_BIN:-}" ]] && validate_go_binary "$GO_BIN" >/dev/null 2>&1; then
                    GO_SOURCE="external"
                    export GO_SOURCE GO_BIN
                    persist_go_selection
                    log_success "Using external Go $(local_go_version "$GO_BIN") at $GO_BIN"
                elif [[ -t 0 ]]; then
                    ask_for_existing_go
                else
                    log_error "GO_INSTALL_MODE=external requires GO_BIN=/path/to/go in non-interactive mode."
                    return 1
                fi
                return 0
                ;;
            *)
                log_error "Unknown GO_INSTALL_MODE='$GO_INSTALL_MODE'. Use managed, system or external."
                return 1
                ;;
        esac
    fi

    # Reuse a persisted/explicit selection first.
    if [[ "$GO_SOURCE" =~ ^(managed|external|system|system-managed)$ ]] && [[ -n "$GO_BIN" ]] && validate_go_binary "$GO_BIN" >/dev/null 2>&1; then
        local current
        current="$(local_go_version "$GO_BIN")"
        persist_go_selection
        log_success "Using $GO_SOURCE Go $current at $GO_BIN (automatic Go toolchain downloads disabled)"
        return 0
    fi

    # Recover an existing managed installation even if its state file was lost.
    if [[ -x "$MANAGED_GO_DIR/bin/go" ]] && validate_go_binary "$MANAGED_GO_DIR/bin/go" >/dev/null 2>&1; then
        GO_SOURCE="managed"
        GO_BIN="$MANAGED_GO_DIR/bin/go"
        export GO_SOURCE GO_BIN
        persist_go_selection
        log_success "Reusing managed Go $(local_go_version "$GO_BIN") at $GO_BIN"
        return 0
    fi

    # If a persisted selection became invalid, fall back to the current system Go.
    local system_go system_version=""
    system_go="$(command -v go 2>/dev/null || true)"
    if [[ -n "$system_go" ]]; then
        system_version="$(local_go_version "$system_go" || true)"
        if [[ -n "$system_version" ]] && version_ge "$system_version" "$GO_VERSION"; then
            GO_SOURCE="system"
            GO_BIN="$(readlink -f "$system_go")"
            export GO_SOURCE GO_BIN
            persist_go_selection
            log_success "Using system Go $system_version at $GO_BIN (Go >= $GO_VERSION required)"
            return 0
        fi
    fi

    echo
    echo "Go dependency decision"
    echo "----------------------"
    if [[ -n "$system_go" && -n "$system_version" ]]; then
        echo "Detected system Go:  $system_version ($system_go)"
        echo "Required minimum:    $GO_VERSION"
        echo "The detected Go version is too old for the pinned SCION checkout."
    else
        echo "Detected system Go:  not found"
        echo "Required minimum:    $GO_VERSION"
    fi
    echo
    echo "Choose how Go should be provided:"
    echo
    echo "  1) Install Go $MANAGED_GO_VERSION ONLY for this testenvironment"
    echo "     -> $MANAGED_GO_DIR"
    echo "     -> does not modify system Go"
    echo
    echo "  2) Install/update Go $MANAGED_GO_VERSION SYSTEM-WIDE"
    echo "     -> $SYSTEM_GO_DIR"
    echo "     -> /usr/local/bin/go will use this version"
    echo "     -> previous /usr/local Go state is preserved for 'uninstall'"
    echo
    echo "  3) Use another existing Go >= $GO_VERSION"
    echo "     -> you provide the path"
    echo

    local choice=""
    case "${GO_INSTALL_MODE:-}" in
        managed|local|testenvironment) choice="1" ;;
        system|system-managed) choice="2" ;;
        external) choice="3" ;;
    esac
    if [[ -z "$choice" && "${AUTO_INSTALL_GO:-}" == "1" ]]; then choice="1"; fi
    if [[ -z "$choice" && "${AUTO_INSTALL_GO:-}" == "0" ]]; then choice="3"; fi

    if [[ -z "$choice" ]]; then
        if [[ -t 0 ]]; then
            read -r -p "Selection [1]: " choice
            choice="${choice:-1}"
        else
            log_error "No compatible Go toolchain is available in a non-interactive run."
            log_error "Set GO_INSTALL_MODE=managed|system|external (and GO_BIN for external)."
            return 1
        fi
    fi

    case "$choice" in
        1)
            install_managed_go
            ;;
        2)
            install_system_go
            ;;
        3)
            if [[ -n "${GO_BIN:-}" ]] && validate_go_binary "$GO_BIN" >/dev/null 2>&1; then
                GO_SOURCE="external"
                export GO_SOURCE GO_BIN
                persist_go_selection
                log_success "Using external Go $(local_go_version "$GO_BIN") at $GO_BIN"
            else
                [[ -t 0 ]] || {
                    log_error "GO_INSTALL_MODE=external requires GO_BIN=/path/to/go in non-interactive mode."
                    return 1
                }
                ask_for_existing_go
            fi
            ;;
        *)
            log_error "Invalid selection '$choice'. Choose 1, 2 or 3."
            return 1
            ;;
    esac
}

install_scitra() {
    if command -v scitra-tun >/dev/null 2>&1 && command -v scion2ip >/dev/null 2>&1; then
        log_success "Scitra-TUN and scion2ip already installed"
        return 0
    fi

    log_info "Installing only the Scitra packages required by the destination host..."
    . /etc/os-release
    local codename="${VERSION_CODENAME:-}"
    [[ -n "$codename" ]] || { log_error "Ubuntu codename not found in /etc/os-release"; return 1; }

    mkdir -p "$INSTALL_STATE_DIR"
    if [[ ! -f /usr/share/keyrings/scion-lcschulz.gpg ]]; then
        curl -fsSL https://lcschulz.de/scion/gpg/scion-lcschulz -o /usr/share/keyrings/scion-lcschulz.gpg
        chmod a+r /usr/share/keyrings/scion-lcschulz.gpg
        touch "$SCION_APT_KEY_MARKER"
    fi

    if [[ ! -f /etc/apt/sources.list.d/scion-lcschulz.list ]]; then
        cat > /etc/apt/sources.list.d/scion-lcschulz.list <<APT
# Required by the local SCION/Scitra integration test environment.
deb [arch=amd64 signed-by=/usr/share/keyrings/scion-lcschulz.gpg] https://lcschulz.de/scion/apt $codename main
APT
        touch "$SCION_APT_SOURCE_MARKER"
    fi

    apt-get update
    install_packages_tracked scitra-tun scion++-tools
    log_success "Scitra-TUN packages are ready"
}

ensure_scion_python_tooling() {
    # cce7754b652c uses Python for topogen and supervisor wildcard control.
    # Install the pinned requirements into testenvironment-owned .deps rather
    # than into Ubuntu's externally-managed system Python.
    local req_marker="$SCION_PYTHON_DEPS_DIR/.requirements-v1"
    local expected="toml==0.10.2 PyYAML==6.0.1 plumbum==1.6.9 supervisor==4.2.5 supervisor-wildcards==0.1.3 six==1.15.0"

    if [[ -f "$req_marker" ]]; then
        if PYTHONPATH="$SCION_PYTHON_DEPS_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 - <<'PYREQ' >/dev/null 2>&1
import toml, yaml, plumbum, supervisor, supervisorwildcards, six
PYREQ
        then
            log_success "SCION Python topology/supervisor dependencies are ready"
            return 0
        fi
    fi

    log_info "Installing pinned SCION Python topology/supervisor dependencies under $SCION_PYTHON_DEPS_DIR ..."
    rm -rf "$SCION_PYTHON_DEPS_DIR"
    mkdir -p "$SCION_PYTHON_DEPS_DIR"
    python3 -m pip install --disable-pip-version-check --no-input \
        --target "$SCION_PYTHON_DEPS_DIR" \
        'toml==0.10.2' \
        'PyYAML==6.0.1' \
        'plumbum==1.6.9' \
        'supervisor==4.2.5' \
        'supervisor-wildcards==0.1.3' \
        'six==1.15.0'
    printf '%s
' "$expected" > "$req_marker"
    if [[ "$RUN_USER" != root ]]; then
        chown -R "$RUN_USER:$RUN_GROUP" "$SCION_PYTHON_DEPS_DIR"
    fi
    log_success "SCION Python topology/supervisor dependencies are ready"
}

persist_scion_selection() {
    mkdir -p "$INSTALL_STATE_DIR"
    {
        printf 'SCION_SOURCE=%q\n' "$SCION_SOURCE"
        printf 'SCION_DIR=%q\n' "$SCION_DIR"
    } > "$SCION_STATE_FILE"
}

normalize_scion_path() {
    local input="$1"
    if [[ "$input" == "~" ]]; then
        input="$RUN_HOME"
    elif [[ "$input" == "~/"* ]]; then
        input="$RUN_HOME/${input:2}"
    fi
    if [[ -f "$input" && "$(basename "$input")" == "scion.sh" ]]; then
        dirname "$(readlink -f "$input")"
    elif [[ -d "$input" ]]; then
        readlink -f "$input"
    else
        printf '%s\n' "$input"
    fi
}

validate_scion_checkout() {
    local dir="$1"
    [[ -d "$dir" ]] || { log_error "SCION directory does not exist: $dir"; return 1; }
    [[ -f "$dir/scion.sh" ]] || { log_error "scion.sh not found in: $dir"; return 1; }
    [[ -f "$dir/go.mod" ]] || { log_error "go.mod not found in: $dir (not a SCION repository root?)"; return 1; }
    [[ -f "$dir/tools/topogen.py" ]] || { log_error "tools/topogen.py not found in: $dir"; return 1; }
    [[ -d "$dir/.git" ]] || { log_error "No .git directory found in: $dir"; return 1; }
}

check_scion_version() {
    local dir="$1" actual=""
    actual="$(git -C "$dir" rev-parse HEAD 2>/dev/null || true)"
    [[ -n "$actual" ]] || { log_warn "Could not determine SCION Git commit for $dir"; return 0; }

    if [[ "$actual" == "$SCION_REF"* || "$SCION_REF" == "$actual"* ]]; then
        log_success "SCION checkout matches expected ref ${SCION_REF} (${actual:0:12})"
        return 0
    fi

    log_warn "The supplied SCION checkout is on a different commit."
    echo "  Expected by this wireguard-go checkout: $SCION_REF"
    echo "  Existing SCION checkout:              ${actual:0:12}"
    echo "A different SCION version can make the generated topology/runtime incompatible with the translator."

    if [[ "${ALLOW_SCION_VERSION_MISMATCH:-0}" == 1 ]]; then
        log_warn "Continuing because ALLOW_SCION_VERSION_MISMATCH=1"
        return 0
    fi

    if [[ ! -t 0 ]]; then
        log_error "Non-interactive run: set ALLOW_SCION_VERSION_MISMATCH=1 to continue with this checkout."
        return 1
    fi

    local reply
    read -r -p "Continue with this SCION checkout anyway? [y/N]: " reply
    [[ "$reply" =~ ^[yY]$ ]] || return 1
}

choose_scion_source() {
    # Reuse a previously selected or explicitly supplied checkout when valid.
    if [[ "$SCION_SOURCE" == "external" ]]; then
        if validate_scion_checkout "$SCION_DIR"; then
            check_scion_version "$SCION_DIR"
            persist_scion_selection
            log_success "Using existing external SCION checkout: $SCION_DIR"
            return 0
        fi
        log_warn "Previously configured external SCION checkout is no longer usable."
        SCION_SOURCE="unconfigured"
        SCION_DIR="$SCION_MANAGED_DIR"
    elif [[ "$SCION_SOURCE" == "managed" && -d "$SCION_DIR/.git" ]]; then
        validate_scion_checkout "$SCION_DIR"
        check_scion_version "$SCION_DIR"
        persist_scion_selection
        log_success "Reusing testenvironment-managed SCION checkout: $SCION_DIR"
        return 0
    fi

    echo
    echo "SCION is required to generate and run the local multi-AS test topology."
    echo "It is the largest additional dependency of this test environment."
    echo

    local reply=""
    if [[ -t 0 ]]; then
        read -r -p "Download/build the required SCION version automatically under .deps/scion? [Y/n]: " reply
    fi

    if [[ -z "$reply" || "$reply" =~ ^[yY]$ ]]; then
        SCION_SOURCE="managed"
        SCION_DIR="$SCION_MANAGED_DIR"
        export SCION_SOURCE SCION_DIR
        persist_scion_selection
        return 0
    fi

    if [[ ! "$reply" =~ ^[nN]$ ]]; then
        log_error "Please answer y or n."
        return 1
    fi

    echo
    echo "This test environment still needs a SCION source checkout."
    echo "Please provide the SCION repository root directory."
    echo "The directory must contain at least: scion.sh, go.mod and tools/topogen.py"
    echo
    echo "Examples:"
    echo "  /home/$RUN_USER/scion"
    echo "  /home/$RUN_USER/scion/scion.sh   (also accepted and normalized to the repo root)"
    echo

    local input candidate
    while true; do
        read -r -p "Path to existing SCION checkout: " input
        candidate="$(normalize_scion_path "$input")"
        if validate_scion_checkout "$candidate"; then
            SCION_SOURCE="external"
            SCION_DIR="$candidate"
            export SCION_SOURCE SCION_DIR
            check_scion_version "$SCION_DIR"
            persist_scion_selection
            log_success "Using external SCION checkout: $SCION_DIR"
            return 0
        fi
        echo
        log_warn "That path is not a usable SCION repository root. Please try again."
    done
}

clone_scion_source() {
    [[ "$SCION_SOURCE" == "managed" ]] || return 0
    mkdir -p "$DEPS_DIR"
    if [[ -d "$SCION_DIR/.git" ]]; then
        return 0
    fi

    log_info "Cloning pinned SCION source into $SCION_DIR ..."
    log_info "Using a partial clone to reduce download/storage overhead."
    rm -rf "$SCION_DIR"
    if [[ "$RUN_USER" != root ]]; then
        chown -R "$RUN_USER:$RUN_GROUP" "$DEPS_DIR"
    fi

    if ! run_as_user git clone --filter=blob:none --no-checkout "$SCION_REPO_URL" "$SCION_DIR"; then
        log_warn "Partial clone unsupported; falling back to a normal clone"
        rm -rf "$SCION_DIR"
        run_as_user git clone "$SCION_REPO_URL" "$SCION_DIR"
    fi
    run_as_user git -C "$SCION_DIR" checkout -q --detach "$SCION_REF"
    persist_scion_selection
}

prepare_scion_helpers() {
    mkdir -p "$SCION_DIR/bin"
    chmod +x "$SCION_DIR/tools/topogen.py"
    [[ -e "$SCION_DIR/bin/topogen" ]] || ln -s ../tools/topogen.py "$SCION_DIR/bin/topogen"
    [[ -e "$SCION_DIR/bin/supervisord" ]] || ln -s "$(command -v supervisord)" "$SCION_DIR/bin/supervisord"
    [[ -e "$SCION_DIR/bin/supervisorctl" ]] || ln -s "$(command -v supervisorctl)" "$SCION_DIR/bin/supervisorctl"
}

build_scion_minimal() {
    local required=(router control dispatcher daemon scion scion-pki)
    local missing=()
    local targets=()
    local f

    for f in "${required[@]}"; do
        [[ -x "$SCION_DIR/bin/$f" ]] || missing+=("$f")
    done

    if ((${#missing[@]} == 0)); then
        log_success "Required SCION binaries already exist; skipping SCION build"
        return 0
    fi

    # Build only package groups whose resulting binaries are actually missing.
    for f in "${missing[@]}"; do
        case "$f" in
            router)     targets+=("./router/...") ;;
            control)    targets+=("./control/...") ;;
            dispatcher) targets+=("./dispatcher/...") ;;
            daemon)     targets+=("./daemon/...") ;;
            scion)      targets+=("./scion/...") ;;
            scion-pki)  targets+=("./scion-pki/...") ;;
        esac
    done

    log_info "Missing SCION binaries: ${missing[*]}"
    log_info "Building only the missing SCION components required by the local topology..."
    log_info "Go dependency/build output is written to: $SCION_BUILD_LOG"
    log_info "Tests, end2end tools, pktgen, buildkite tools, gateway, etc. are NOT built."

    mkdir -p "$GO_MOD_CACHE" "$GO_BUILD_CACHE" "$(dirname "$SCION_BUILD_LOG")"
    : > "$SCION_BUILD_LOG"
    if [[ "$RUN_USER" != root ]]; then
        chown -R "$RUN_USER:$RUN_GROUP" "$DEPS_DIR"
    fi

    # The output redirection is intentionally outside run_as_user so the root
    # orchestrator can always create/write the testenvironment-owned log file.
    # GOTOOLCHAIN=local prevents Go from downloading a second Go toolchain.
    local target_args=""
    printf -v target_args ' %q' "${targets[@]}"

    if ! run_as_user env \
        PATH="$(dirname "$GO_BIN"):/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        GOTOOLCHAIN=local \
        GOMODCACHE="$GO_MOD_CACHE" \
        GOCACHE="$GO_BUILD_CACHE" \
        CGO_ENABLED=0 \
        bash -lc "cd $(printf '%q' "$SCION_DIR") && $(printf '%q' "$GO_BIN") build -o bin${target_args}" \
        >>"$SCION_BUILD_LOG" 2>&1; then
        log_error "SCION build failed. Last 30 log lines:"
        tail -n 30 "$SCION_BUILD_LOG" >&2 || true
        log_error "Full SCION build log: $SCION_BUILD_LOG"
        return 1
    fi

    for f in "${required[@]}"; do
        [[ -x "$SCION_DIR/bin/$f" ]] || {
            log_error "Expected SCION binary missing after build: $SCION_DIR/bin/$f"
            log_error "Full SCION build log: $SCION_BUILD_LOG"
            return 1
        }
    done
    log_success "Required SCION binaries are ready"
}

setup_scion_source() {
    choose_scion_source
    clone_scion_source
    validate_scion_checkout "$SCION_DIR"
    prepare_scion_helpers
    build_scion_minimal
    log_success "SCION source environment ready ($SCION_SOURCE: $SCION_DIR)"
}

verify() {
    local cmd
    for cmd in ip curl git wg socat jq python3 supervisord supervisorctl scitra-tun scion2ip; do
        check_command "$cmd"
    done
    [[ -n "$GO_BIN" && -x "$GO_BIN" ]]
    [[ -x "$SCION_DIR/scion.sh" ]]
    [[ -x "$SCION_DIR/bin/topogen" ]]
    [[ -x "$SCION_DIR/bin/router" ]]
    [[ -x "$SCION_DIR/bin/control" ]]
    [[ -x "$SCION_DIR/bin/dispatcher" ]]
    [[ -x "$SCION_DIR/bin/daemon" ]]
    [[ -x "$SCION_DIR/bin/scion" ]]
    [[ -x "$SCION_DIR/bin/scion-pki" ]]
}

create_directories
install_host_packages
ensure_go
prepare_go_cache_dirs
install_scitra
ensure_scion_python_tooling
setup_scion_source
verify
log_success "All dependencies are ready"
