#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
check_root

SUPERVISOR_SOCKET="/tmp/supervisor.sock"
SUPERVISOR_PIDFILE="/tmp/supervisord.pid"

supervisor_pid_from_socket() {
    [[ -S "$SUPERVISOR_SOCKET" ]] || return 1
    local out
    out="$(cd "$SCION_DIR" && "$SCION_DIR/bin/supervisorctl" -c tools/supervisord.conf pid 2>/dev/null || true)"
    [[ "$out" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$out"
}

pid_belongs_to_this_scion_checkout() {
    local pid="$1" cwd=""
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    cwd="$(readlink -f "/proc/$pid/cwd" 2>/dev/null || true)"
    [[ "$cwd" == "$(readlink -f "$SCION_DIR")" ]]
}

cleanup_supervisor_state() {
    local pid=""

    # The SCION checkout used here hard-codes /tmp/supervisor.sock and
    # /tmp/supervisord.pid in tools/supervisord.conf/tools/supervisor.sh.
    # A previous namespace run can therefore leave a dead socket behind even
    # though all SCION processes were killed with the namespace. That exact
    # stale socket caused "unix:///tmp/supervisor.sock refused connection".
    if pid="$(supervisor_pid_from_socket 2>/dev/null)"; then
        if pid_belongs_to_this_scion_checkout "$pid"; then
            log_info "Stopping previous SCION supervisord (pid $pid) before restart ..."
            (cd "$SCION_DIR" && "$SCION_DIR/bin/supervisorctl" -c tools/supervisord.conf shutdown >/dev/null 2>&1) || true
            for _ in {1..30}; do kill -0 "$pid" 2>/dev/null || break; sleep .1; done
            kill "$pid" 2>/dev/null || true
        else
            log_error "$SUPERVISOR_SOCKET belongs to a live supervisord process outside $SCION_DIR"
            log_error "SCION's supervisor tooling hard-codes this socket and cannot safely share it."
            return 1
        fi
    elif [[ -f "$SUPERVISOR_PIDFILE" ]]; then
        pid="$(cat "$SUPERVISOR_PIDFILE" 2>/dev/null || true)"
        if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
            if pid_belongs_to_this_scion_checkout "$pid"; then
                log_info "Stopping previous SCION supervisord from pidfile (pid $pid) ..."
                kill "$pid" 2>/dev/null || true
                for _ in {1..30}; do kill -0 "$pid" 2>/dev/null || break; sleep .1; done
                kill -9 "$pid" 2>/dev/null || true
            else
                log_error "$SUPERVISOR_PIDFILE points to a live process outside $SCION_DIR (pid $pid)"
                return 1
            fi
        fi
    fi

    # If supervisorctl could not connect, any remaining socket/pidfile is stale.
    rm -f "$SUPERVISOR_SOCKET" "$SUPERVISOR_PIDFILE"
    log_success "SCION supervisor state is clean"
}

run_showpaths_check() {
    local ns="$1" daemon="$2" destination="$3" mode="$4" logfile="$5"
    local latest="${logfile}.latest"
    local -a args=(showpaths --sciond "$daemon" --refresh)
    [[ "$mode" == "control" ]] && args+=(--no-probe)
    args+=("$destination")

    if timeout "${SCION_PATH_QUERY_TIMEOUT}s" \
        ip netns exec "$ns" "$SCION_DIR/bin/scion" "${args[@]}" \
        >"$latest" 2>&1; then
        {
            echo "===== $(date -Is) | $mode | $ns | $destination ====="
            cat "$latest"
            echo
        } >> "$logfile"
        if [[ "$mode" == "alive" ]]; then
            grep -q 'Status: alive' "$latest"
        else
            return 0
        fi
    else
        {
            echo "===== $(date -Is) | $mode | $ns | $destination | NOT READY ====="
            cat "$latest" 2>/dev/null || true
            echo
        } >> "$logfile"
        return 1
    fi
}

wait_for_scion_path_convergence() {
    local start now elapsed
    local target_control=0 source_control=0
    local stable=0 target_alive=0 source_alive=0
    local target_log="$LOGS_DIR/scion-path-target-to-source.log"
    local source_log="$LOGS_DIR/scion-path-source-to-target.log"

    : > "$target_log"
    : > "$source_log"
    start="$(date +%s)"

    log_info "Waiting for SCION paths to converge (poll ${SCION_PATH_READY_INTERVAL}s, max ${SCION_PATH_READY_TIMEOUT}s) ..."
    log_info "Required: $TARGET_IA -> $SOURCE_IA and $SOURCE_IA -> $TARGET_IA, then ${SCION_PATH_STABLE_SUCCESSES} consecutive alive confirmations."

    while :; do
        now="$(date +%s)"
        elapsed=$((now - start))
        if (( elapsed >= SCION_PATH_READY_TIMEOUT )); then
            break
        fi

        if (( target_control == 0 )); then
            if run_showpaths_check "$SCITRA_NS" "$SCITRA_DAEMON_ADDR" "$SOURCE_IA" control "$target_log"; then
                target_control=1
                log_success "Control-plane path $TARGET_IA -> $SOURCE_IA is available (${elapsed}s)"
            fi
        fi

        if (( source_control == 0 )); then
            if run_showpaths_check "$SERVER_NS" "$SOURCE_DAEMON_ADDR" "$TARGET_IA" control "$source_log"; then
                source_control=1
                log_success "Control-plane path $SOURCE_IA -> $TARGET_IA is available (${elapsed}s)"
            fi
        fi

        target_alive=0
        source_alive=0
        if (( target_control == 1 && source_control == 1 )); then
            if run_showpaths_check "$SCITRA_NS" "$SCITRA_DAEMON_ADDR" "$SOURCE_IA" alive "$target_log"; then
                target_alive=1
            fi
            if run_showpaths_check "$SERVER_NS" "$SOURCE_DAEMON_ADDR" "$TARGET_IA" alive "$source_log"; then
                source_alive=1
            fi

            if (( target_alive == 1 && source_alive == 1 )); then
                stable=$((stable + 1))
                log_info "Alive SCION paths confirmed in both directions (${stable}/${SCION_PATH_STABLE_SUCCESSES})"
                if (( stable >= SCION_PATH_STABLE_SUCCESSES )); then
                    now="$(date +%s)"
                    elapsed=$((now - start))
                    log_success "SCION control/data plane is stable in both directions after ${elapsed}s"
                    rm -f "${target_log}.latest" "${source_log}.latest"
                    return 0
                fi
            else
                stable=0
            fi
        fi

        now="$(date +%s)"
        elapsed=$((now - start))
        log_info "SCION path readiness ${elapsed}s/${SCION_PATH_READY_TIMEOUT}s | control T->S=${target_control} S->T=${source_control} | alive T->S=${target_alive} S->T=${source_alive} | stable=${stable}/${SCION_PATH_STABLE_SUCCESSES}"
        sleep "$SCION_PATH_READY_INTERVAL"
    done

    log_error "SCION paths did not become stable within ${SCION_PATH_READY_TIMEOUT}s"
    echo "--- latest $TARGET_IA -> $SOURCE_IA lookup ---" >&2
    tail -n 40 "${target_log}.latest" >&2 2>/dev/null || tail -n 40 "$target_log" >&2 || true
    echo "--- latest $SOURCE_IA -> $TARGET_IA lookup ---" >&2
    tail -n 40 "${source_log}.latest" >&2 2>/dev/null || tail -n 40 "$source_log" >&2 || true
    log_error "Full path readiness logs: $target_log and $source_log"
    return 1
}

print_scion_diagnostics() {
    echo "--- supervisor status ---" >&2
    ip netns exec "$SERVER_NS" bash -c "cd '$SCION_DIR' && ./tools/supervisor.sh status" >&2 || true
    echo "--- daemon listeners ---" >&2
    ip netns exec "$SERVER_NS" ss -lntp >&2 || true
    echo "--- last SCION start log lines ---" >&2
    tail -n 60 "$LOGS_DIR/scion-start.log" >&2 || true
    if [[ -f "$SCION_DIR/logs/supervisord.log" ]]; then
        echo "--- last supervisord log lines ---" >&2
        tail -n 60 "$SCION_DIR/logs/supervisord.log" >&2 || true
    fi
}

start_scion() {
    load_runtime_env
    [[ -d "$SCION_DIR/gen/AS$SOURCE_ASN" ]] || { log_error "SCION topology missing"; return 1; }
    ip netns exec "$SERVER_NS" ip link show "$WG_SERVER_IFACE" >/dev/null 2>&1 || { log_error "wg-server must be up before SCION"; return 1; }

    cleanup_supervisor_state

    : > "$LOGS_DIR/scion-start.log"
    log_info "Starting SCION local topology inside $SERVER_NS ..."
    if ! ip netns exec "$SERVER_NS" bash -c "cd '$SCION_DIR' && ./scion.sh run" \
        > >(tee "$LOGS_DIR/scion-start.log") 2>&1; then
        log_error "scion.sh run returned an error"
        print_scion_diagnostics
        return 1
    fi

    # Do not treat the existence of the supervisor socket as sufficient. SCION's
    # own status command returns success only when all generated supervisor
    # programs are RUNNING.
    if ! wait_for 30 "all SCION supervisor services to become RUNNING" \
        "ip netns exec '$SERVER_NS' bash -c \"cd '$SCION_DIR' && ./scion.sh status >/dev/null 2>&1\""; then
        print_scion_diagnostics
        return 1
    fi
    log_success "All generated SCION supervisor services are RUNNING"

    if ! wait_for 30 "source SCION daemon $SOURCE_DAEMON_ADDR" \
        "ip netns exec '$SERVER_NS' ss -lntH | grep -Fq '$SOURCE_DAEMON_ADDR'"; then
        print_scion_diagnostics
        return 1
    fi
    log_success "Source SCION daemon listening at $SOURCE_DAEMON_ADDR"

    if [[ -n "${SOURCE_CONTROL_ADDR:-}" ]]; then
        if ! wait_for 30 "source Control/Discovery Service $SOURCE_CONTROL_ADDR" \
            "ip netns exec '$SERVER_NS' ss -lntH | grep -Fq '$SOURCE_CONTROL_ADDR'"; then
            log_error "Source Control/Discovery Service did not bind to the patched WG-routable address."
            log_error "Expected: $SOURCE_CONTROL_ADDR"
            print_scion_diagnostics
            return 1
        fi
        log_success "Source Control/Discovery Service listening at $SOURCE_CONTROL_ADDR"
    fi

    if ! wait_for 30 "target SCION daemon $SCITRA_DAEMON_ADDR" \
        "ip netns exec '$SERVER_NS' ss -lntH | grep -Fq '$SCITRA_DAEMON_ADDR'"; then
        print_scion_diagnostics
        return 1
    fi
    log_success "Target SCION daemon listening at $SCITRA_DAEMON_ADDR"

    # Services being RUNNING is not enough: beacon origination/propagation and
    # path registration need time. Wait actively for stable paths in both
    # directions before any Scitra component is started.
    if ! wait_for_scion_path_convergence; then
        print_scion_diagnostics
        return 1
    fi

    log_success "SCION infrastructure started cleanly and paths are READY"
}

stop_scion() {
    if [[ -x "$SCION_DIR/scion.sh" ]] && is_namespace_running "$SERVER_NS"; then
        ip netns exec "$SERVER_NS" bash -c "cd '$SCION_DIR' && ./scion.sh stop" 2>/dev/null || true
    fi
    cleanup_supervisor_state 2>/dev/null || true
}

status() {
    if ! is_namespace_running "$SERVER_NS"; then echo "$SERVER_NS not running"; return 0; fi
    echo "Supervisor socket: $SUPERVISOR_SOCKET"
    if [[ -S "$SUPERVISOR_SOCKET" ]]; then
        ip netns exec "$SERVER_NS" bash -c "cd '$SCION_DIR' && ./tools/supervisor.sh status" 2>/dev/null || true
    else
        echo "Supervisor socket not present"
    fi
    echo; echo "SCION daemon/control listeners:"; ip netns exec "$SERVER_NS" ss -lnt | grep -E '30255|31000|10\.0\.0\.6' || true
}

case "${1:-}" in
    prepare) cleanup_supervisor_state ;;
    up) log_step "SCION services"; start_scion ;;
    down) stop_scion ;;
    status) status ;;
    *) echo "Usage: $0 {prepare|up|down|status}"; exit 2 ;;
esac
