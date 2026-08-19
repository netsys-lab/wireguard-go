#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
check_root

RUN_USER="${SUDO_USER:-root}"
WG_BUILD_LOG="$LOGS_DIR/wireguard-build.log"
REPO_WG_BINARY="$REPO_ROOT/wireguard-go"

build_wireguard_go() {
    [[ -f "$REPO_ROOT/go.mod" ]] || { log_error "go.mod not found at repository root: $REPO_ROOT"; return 1; }
    log_info "Building custom wireguard-go from $REPO_ROOT"
    if [[ -f "$REPO_WG_BINARY" ]]; then
        log_success "Existing wireguard-go binary found in project root: $REPO_WG_BINARY"
        log_info "Refreshing it with 'go build'; Go reuses its persistent build cache and recompiles only what changed."
    else
        log_info "No wireguard-go binary found in project root yet; creating $REPO_WG_BINARY"
    fi
    log_info "Go download/build output is written to: $WG_BUILD_LOG"

    mkdir -p "$BIN_DIR" "$GO_MOD_CACHE" "$GO_BUILD_CACHE" "$LOGS_DIR"
    : > "$WG_BUILD_LOG"

    local build_pid rc=0
    local heartbeat_interval="${BUILD_HEARTBEAT_SECONDS:-5}"
    local started_at=$SECONDS

    if [[ "$RUN_USER" == root ]]; then
        (
            cd "$REPO_ROOT"
            GOTOOLCHAIN=local GOMODCACHE="$GO_MOD_CACHE" GOCACHE="$GO_BUILD_CACHE" GOPROXY=https://proxy.golang.org,direct \
                "$GO_BIN" build -o "$REPO_WG_BINARY" .
        ) >>"$WG_BUILD_LOG" 2>&1 &
        build_pid=$!
    else
        chown -R "$RUN_USER":"$(id -gn "$RUN_USER")" "$RUNTIME_DIR" "$GO_MOD_CACHE" "$GO_BUILD_CACHE"
        # Older sudo-based runs may have left the repo build artifact root-owned.
        # It is only a generated binary, so hand it back to the repository owner
        # before refreshing it as the invoking user.
        if [[ -e "$REPO_WG_BINARY" && ! -w "$REPO_WG_BINARY" ]]; then
            chown "$RUN_USER":"$(id -gn "$RUN_USER")" "$REPO_WG_BINARY"
        fi
        sudo -u "$RUN_USER" -H env \
            PATH="$(dirname "$GO_BIN"):$PATH" \
            GOTOOLCHAIN=local \
            GOMODCACHE="$GO_MOD_CACHE" \
            GOCACHE="$GO_BUILD_CACHE" \
            GOPROXY=https://proxy.golang.org,direct \
            bash -lc "cd '$REPO_ROOT' && '$GO_BIN' build -o '$REPO_WG_BINARY' ." \
            >>"$WG_BUILD_LOG" 2>&1 &
        build_pid=$!
    fi

    # Keep the main terminal visibly alive while the verbose Go output stays in
    # the dedicated log file. This avoids making a long first build look frozen.
    while kill -0 "$build_pid" 2>/dev/null; do
        sleep "$heartbeat_interval"
        if kill -0 "$build_pid" 2>/dev/null; then
            local elapsed=$((SECONDS - started_at))
            local latest=""
            latest="$(tail -n 1 "$WG_BUILD_LOG" 2>/dev/null | tr -d '\r' | cut -c1-100 || true)"
            if [[ -n "$latest" ]]; then
                log_info "wireguard-go build still running... ${elapsed}s elapsed | latest: $latest"
            else
                log_info "wireguard-go build still running... ${elapsed}s elapsed"
            fi
        fi
    done

    if wait "$build_pid"; then
        rc=0
    else
        rc=$?
    fi

    if (( rc != 0 )); then
        log_error "wireguard-go build failed (exit $rc)"
        echo "--- Last 30 build log lines ---" >&2
        tail -n 30 "$WG_BUILD_LOG" >&2 || true
        echo "Full log: $WG_BUILD_LOG" >&2
        return "$rc"
    fi

    [[ -x "$REPO_WG_BINARY" ]] || { log_error "wireguard-go build did not create $REPO_WG_BINARY"; return 1; }
    ln -sfn "$REPO_WG_BINARY" "$BIN_DIR/wireguard-go"
    log_success "Custom wireguard-go refreshed and ready: $REPO_WG_BINARY"
}

generate_keys() {
    mkdir -p "$KEYS_DIR"
    if [[ ! -s "$KEYS_DIR/server_private" ]]; then
        wg genkey | tee "$KEYS_DIR/server_private" | wg pubkey > "$KEYS_DIR/server_public"
    fi
    if [[ ! -s "$KEYS_DIR/client_private" ]]; then
        wg genkey | tee "$KEYS_DIR/client_private" | wg pubkey > "$KEYS_DIR/client_public"
    fi
    chmod 600 "$KEYS_DIR"/*_private
    log_success "WireGuard keys ready"
}

case "${1:-}" in
    build) log_step "Build"; create_directories; build_wireguard_go; generate_keys ;;
    clean) rm -f "$BIN_DIR/wireguard-go" "$KEYS_DIR"/* 2>/dev/null || true ;;
    status) ls -l "$BIN_DIR/wireguard-go" "$KEYS_DIR"/* 2>/dev/null || true ;;
    *) echo "Usage: $0 {build|clean|status}"; exit 2 ;;
esac
