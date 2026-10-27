#!/usr/bin/env bash
set -uo pipefail

# Determine script base directory regardless of where it is invoked
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IP_DOCROOT="$SCRIPT_DIR/website/ip"
SCION_DOCROOT="$SCRIPT_DIR/website/scion"

TARGET_IP_URL="http://10.30.34.100:8080/"
SCION_MAPPED_URL="http://[fc00:30fc:1600::ffff:a1e:2264]:8000/"

TARGET_IP="10.30.34.100"
SCION_MAPPED_IP="fc00:30fc:1600::ffff:a1e:2264"
IPERF_PORT=5201
IPERF_PLAIN_PORT=5200
IPERF_DURATION=5

DO_PROFILE=0
for arg in "$@"; do
    case "$arg" in
        --profile)
            DO_PROFILE=1
            ;;
        -h|--help)
            echo "Usage: $0 [--profile]"
            echo "  --profile    Record CPU (10s) and memory allocs using pprof during benchmark"
            exit 0
            ;;
    esac
done

ITERATIONS=10
CLIENT_MODE_FILE="$SCRIPT_DIR/.runtime/state/client-mode"
LOGS_DIR="$SCRIPT_DIR/.runtime/logs"
CLIENT_SCITRA_MODE=0
CLIENT_RESULT_LABEL="Target (Custom Go Translator)"
CLIENT_IPERF_PREFIX="Go Trans"
if [[ -r "$CLIENT_MODE_FILE" ]] && [[ "$(<"$CLIENT_MODE_FILE")" == "scitra" ]]; then
    CLIENT_SCITRA_MODE=1
    CLIENT_RESULT_LABEL="Baseline B (Scitra-TUN in Client)"
    CLIENT_IPERF_PREFIX="Client Scitra"
fi

echo "============================================================"
echo " UNIFIED SCION TRANSLATOR BENCHMARK & DIAGNOSTIC SUITE"
echo " Client result: $CLIENT_RESULT_LABEL"
if [[ "$DO_PROFILE" -eq 1 ]]; then
    echo " Profiler:     ENABLED (pprof CPU 10s & Memory Allocs)"
fi
echo "============================================================"

# --- CLEANUP TRAP ---
PID_CPU_PROF=""
PID_ALLOC_PROF=""
cleanup() {
    sudo ip netns exec ScitraServer pkill -f "iperf3" 2>/dev/null || true
    if [[ -n "${PID_CPU_PROF:-}" ]]; then kill "$PID_CPU_PROF" 2>/dev/null || true; fi
    if [[ -n "${PID_ALLOC_PROF:-}" ]]; then kill "$PID_ALLOC_PROF" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

# --- PROFILING HELPERS ---
PROFILE_STARTED=0
start_profiling() {
    if [[ "$DO_PROFILE" -eq 1 && "$PROFILE_STARTED" -eq 0 ]]; then
        PROFILE_STARTED=1
        echo -e "\n\033[1;36m[PROFILER] Starting background CPU (10s) and memory allocs capture in Client...\033[0m"
        mkdir -p "$LOGS_DIR"
        sudo ip netns exec Client curl -s "http://127.0.0.1:6060/debug/pprof/profile?seconds=10" > "$LOGS_DIR/cpu.prof" 2>/dev/null &
        PID_CPU_PROF=$!
        sudo ip netns exec Client curl -s "http://127.0.0.1:6060/debug/pprof/allocs" > "$LOGS_DIR/allocs.prof" 2>/dev/null &
        PID_ALLOC_PROF=$!
    fi
}

wait_profiling() {
    if [[ "$DO_PROFILE" -eq 1 && -n "${PID_CPU_PROF:-}" ]]; then
        echo -e "\033[1;36m[PROFILER] Waiting for profiling data collection to complete...\033[0m"
        wait "$PID_CPU_PROF" 2>/dev/null || true
        wait "$PID_ALLOC_PROF" 2>/dev/null || true
        PID_CPU_PROF=""
        PID_ALLOC_PROF=""

        if [ -s "$LOGS_DIR/cpu.prof" ]; then
            go tool pprof -top "$LOGS_DIR/cpu.prof" > "$LOGS_DIR/cpu_top.txt" 2>/dev/null || true
            echo -e "\033[1;32m[PROFILER] Top CPU consumers written to: $LOGS_DIR/cpu_top.txt\033[0m"
        fi
        if [ -s "$LOGS_DIR/allocs.prof" ]; then
            go tool pprof -top -alloc_space "$LOGS_DIR/allocs.prof" > "$LOGS_DIR/allocs_top.txt" 2>/dev/null || true
            echo -e "\033[1;32m[PROFILER] Top memory allocations written to: $LOGS_DIR/allocs_top.txt\033[0m"
        fi
    fi
}

# --- 0. PREPARE 50MB TEST PAYLOADS ---
prepare_payloads() {
    echo -n "Checking 50MB test payloads in docroots... "
    mkdir -p "$IP_DOCROOT" "$SCION_DOCROOT"
    
    local ip_file="$IP_DOCROOT/test_50mb.bin"
    local scion_file="$SCION_DOCROOT/test_50mb.bin"
    
    local ip_size=0
    if [ -f "$ip_file" ]; then ip_size=$(stat -c%s "$ip_file" 2>/dev/null || echo 0); fi
    
    if [ "$ip_size" -ne 52428800 ]; then
        echo -n "Generating 50MB payload... "
        dd if=/dev/urandom of="$ip_file" bs=1M count=50 status=none
        chmod 644 "$ip_file"
    fi

    # Link to SCION docroot
    if [ ! -f "$scion_file" ] || [ "$(stat -c%s "$scion_file" 2>/dev/null || echo 0)" -ne 52428800 ]; then
        ln -f "$ip_file" "$scion_file" 2>/dev/null || cp "$ip_file" "$scion_file"
        chmod 644 "$scion_file"
    fi
    echo "Ready."
}

prepare_payloads

# --- 1. LATENCY BENCHMARK (HTTP) ---
measure_latency() {
    local netns="$1"
    local url="$2"
    local label="$3"
    
    echo -n "Measuring Latency: ${label}... "
    local total_connect=0
    local total_ttfb=0
    local total_time=0
    local success=0

    for i in $(seq 1 "$ITERATIONS"); do
        res=$(sudo ip netns exec "$netns" curl -g -s -o /dev/null \
            --connect-timeout 2 --max-time 4 \
            -w "%{time_connect} %{time_starttransfer} %{time_total} %{http_code}" "$url" || echo "0 0 0 000")
        
        read -r c_time ttfb t_time http_code <<< "$res"

        if [[ "$http_code" =~ ^(200|301|302)$ ]]; then
            total_connect=$(awk "BEGIN {print $total_connect + $c_time}")
            total_ttfb=$(awk "BEGIN {print $total_ttfb + $ttfb}")
            total_time=$(awk "BEGIN {print $total_time + $t_time}")
            success=$((success + 1))
        fi
    done

    if [ "$success" -gt 0 ]; then
        avg_connect=$(awk "BEGIN {printf \"%.2f\", ($total_connect / $success) * 1000}")
        avg_ttfb=$(awk "BEGIN {printf \"%.2f\", ($total_ttfb / $success) * 1000}")
        avg_time=$(awk "BEGIN {printf \"%.2f\", ($total_time / $success) * 1000}")
        echo "Done ($success/$ITERATIONS ok)."
        echo "   -> TCP Connect: ${avg_connect} ms | TTFB: ${avg_ttfb} ms | Total: ${avg_time} ms"
    else
        echo "FAILED"
    fi
}

echo ""
echo "--- [1/4] Connection & Processing Latency (HTTP) ---"
measure_latency "Server" "$TARGET_IP_URL" "Baseline A (Plain IP)"
if [[ "$CLIENT_SCITRA_MODE" == 1 ]]; then
    measure_latency "Client" "$SCION_MAPPED_URL" "Baseline B (Scitra-TUN in Client)"
else
    measure_latency "Server" "$SCION_MAPPED_URL" "Baseline B (Reference Scitra-TUN)"
    measure_latency "Client" "$SCION_MAPPED_URL" "$CLIENT_RESULT_LABEL"
fi

# --- 2. HTTP 50MB SUSTAINED THROUGHPUT ---
measure_throughput() {
    local netns="$1"
    local base_url="$2"
    local label="$3"
    local file_url="${base_url%/}/test_50mb.bin"

    echo -n "Measuring 50MB Bulk Transfer: ${label}... "
    local total_speed=0
    local runs=3
    local success=0

    for i in $(seq 1 "$runs"); do
        speed_res=$(sudo ip netns exec "$netns" curl -g -s -o /dev/null \
            --connect-timeout 3 --max-time 100 \
            -w "%{speed_download} %{http_code}" "$file_url" || echo "0 000")
        
        read -r dl_speed http_code <<< "$speed_res"

        if [[ "$http_code" =~ ^(200|301|302)$ ]] && [ "$dl_speed" != "0" ]; then
            total_speed=$(awk "BEGIN {print $total_speed + $dl_speed}")
            success=$((success + 1))
        fi
    done

    if [ "$success" -gt 0 ]; then
        avg_mbps=$(awk "BEGIN {printf \"%.2f\", (($total_speed / $success) * 8) / 1000000}")
        echo "Done (${success}/${runs} ok)."
        echo "   -> Average Sustained Throughput: ${avg_mbps} Mbps"
    else
        echo "FAILED (HTTP Code: ${http_code:-None})"
    fi
}

echo ""
echo "--- [2/4] Sustained HTTP Bulk Throughput (50MB Transfer) ---"
measure_throughput "Server" "$TARGET_IP_URL" "Baseline A (Plain IP)"
if [[ "$CLIENT_SCITRA_MODE" == 1 ]]; then
    start_profiling
    measure_throughput "Client" "$SCION_MAPPED_URL" "Baseline B (Scitra-TUN in Client)"
    wait_profiling
else
    measure_throughput "Server" "$SCION_MAPPED_URL" "Baseline B (Reference Scitra-TUN)"
    start_profiling
    measure_throughput "Client" "$SCION_MAPPED_URL" "$CLIENT_RESULT_LABEL"
    wait_profiling
fi

# --- 3. CONCURRENT LOAD / REQUEST RATE ---
run_load_test() {
    local netns="$1"
    local url="$2"
    local label="$3"

    echo "Running Concurrency Test: ${label} (10 parallel clients, 200 total requests)..."
    
    local start_time
    start_time=$(date +%s%N)
    
    for p in {1..10}; do
        (
            for r in {1..20}; do
                sudo ip netns exec "$netns" curl -g -s -o /dev/null --max-time 3 "$url" || true
            done
        ) &
    done
    wait
    
    local end_time
    end_time=$(date +%s%N)
    local elapsed_sec
    elapsed_sec=$(awk "BEGIN {printf \"%.3f\", ($end_time - $start_time) / 1000000000}")
    local rps
    rps=$(awk "BEGIN {printf \"%.1f\", 200 / $elapsed_sec}")
    
    echo "   -> Completed 200 requests in ${elapsed_sec}s (${rps} Req/Sec)"
}

echo ""
echo "--- [3/4] Concurrency & Flow Scaling ---"
run_load_test "Server" "$TARGET_IP_URL" "Baseline A (Plain IP)"
if [[ "$CLIENT_SCITRA_MODE" == 1 ]]; then
    run_load_test "Client" "$SCION_MAPPED_URL" "Baseline B (Scitra-TUN in Client)"
else
    run_load_test "Server" "$SCION_MAPPED_URL" "Baseline B (Reference Scitra-TUN)"
    run_load_test "Client" "$SCION_MAPPED_URL" "$CLIENT_RESULT_LABEL"
fi

# --- 4. L4 TRANSPORT & PACKET LOSS DIAGNOSTICS (iperf3) ---
echo ""
echo "--- [4/4] L4 Transport Layer Diagnostics (iperf3) ---"

# 1. Clean up any existing iperf3 servers
sudo ip netns exec ScitraServer pkill -f "iperf3" 2>/dev/null || true
sleep 1

# 2. Start iperf3 servers with specific IP bindings:
# Plain IP listener on IPv4 (Port 5200)
sudo ip netns exec ScitraServer iperf3 -s -B "$TARGET_IP" -p "$IPERF_PLAIN_PORT" -D
# SCION listener on mapped IPv6 (Port 5201, bound specifically to scion TUN IP)
sudo ip netns exec ScitraServer iperf3 -s -B "$SCION_MAPPED_IP" -p "$IPERF_PORT" -D
sleep 1

# Function to clean up iperf3 servers when diagnostics finish
cleanup_iperf_server() {
    sudo ip netns exec ScitraServer pkill -f "iperf3" 2>/dev/null || true
}

run_iperf_tcp() {
    local netns="$1"
    local target_ip="$2"
    local mode="$3"
    local is_v6="$4"
    local label="$5"
    local port="${6:-$IPERF_PORT}"

    local v6_arg=""
    if [ "$is_v6" = "true" ]; then v6_arg="-6"; fi

    local r_arg=""
    if [ "$mode" = "download" ]; then r_arg="-R"; fi

    echo -n "  [TCP $mode] ${label}... "

    local json_output
    json_output=$(sudo ip netns exec "$netns" iperf3 $v6_arg -c "$target_ip" -p "$port" \
        -t "$IPERF_DURATION" $r_arg -J 2>/dev/null || echo "{}")

    local error_msg
    error_msg=$(echo "$json_output" | jq -r '.error // empty' 2>/dev/null || true)
    if [ -n "$error_msg" ] || [ "$json_output" = "{}" ]; then
        echo "FAILED (${error_msg:-Connection Timeout/Refused})"
        return
    fi

    local mbps retransmits mean_rtt
    mbps=$(echo "$json_output" | jq -r '(.end.sum_received.bits_per_second // 0) / 1000000 | floor * 100 / 100')
    retransmits=$(echo "$json_output" | jq -r '.end.sum_sent.retransmits // 0')
    mean_rtt=$(echo "$json_output" | jq -r '(.end.streams[0].sender.mean_rtt // 0) / 1000 | floor * 100 / 100')

    printf "Throughput: %'8.2f Mbps | Retransmits: %'4d | Avg RTT: %'6.2f ms\n" "$mbps" "$retransmits" "$mean_rtt"
}

run_iperf_udp() {
    local netns="$1"
    local target_ip="$2"
    local target_bw="$3"
    local is_v6="$4"
    local label="$5"
    local port="${6:-$IPERF_PORT}"

    local v6_arg=""
    if [ "$is_v6" = "true" ]; then v6_arg="-6"; fi

    echo -n "  [UDP @ $target_bw] ${label}... "

    local json_output
    json_output=$(sudo ip netns exec "$netns" iperf3 $v6_arg -c "$target_ip" -p "$port" \
        -u -b "$target_bw" -t "$IPERF_DURATION" -J 2>/dev/null || echo "{}")

    local error_msg
    error_msg=$(echo "$json_output" | jq -r '.error // empty' 2>/dev/null || true)
    if [ -n "$error_msg" ] || [ "$json_output" = "{}" ]; then
        echo "FAILED (${error_msg:-Connection Timeout/Refused})"
        return
    fi

    local actual_mbps loss_pct jitter_ms
    actual_mbps=$(echo "$json_output" | jq -r '(.end.sum.bits_per_second // 0) / 1000000 | floor * 100 / 100')
    loss_pct=$(echo "$json_output" | jq -r '(.end.sum.lost_percent // 0) | floor * 100 / 100')
    jitter_ms=$(echo "$json_output" | jq -r '(.end.sum.jitter_ms // 0) | floor * 100 / 100')

    printf "Delivered: %'7.2f Mbps | Loss: %'5.2f%% | Jitter: %'5.2f ms\n" "$actual_mbps" "$loss_pct" "$jitter_ms"
}

echo "1. Baseline A (Plain IP):"
run_iperf_tcp "Server" "$TARGET_IP" "download" "false" "Plain IP Download" "$IPERF_PLAIN_PORT"
run_iperf_tcp "Server" "$TARGET_IP" "upload"   "false" "Plain IP Upload  " "$IPERF_PLAIN_PORT"
run_iperf_udp "Server" "$TARGET_IP" "30M"      "false" "Plain IP Stream  " "$IPERF_PLAIN_PORT"

if [[ "$CLIENT_SCITRA_MODE" == 1 ]]; then
    echo "2. Baseline B (Scitra-TUN in Client):"
    run_iperf_tcp "Client" "$SCION_MAPPED_IP" "download" "true" "Client Scitra Download" "$IPERF_PORT"
    run_iperf_tcp "Client" "$SCION_MAPPED_IP" "upload"   "true" "Client Scitra Upload  " "$IPERF_PORT"
    run_iperf_udp "Client" "$SCION_MAPPED_IP" "10M"      "true" "Client Scitra Stream  " "$IPERF_PORT"
else
    echo "2. Baseline B (Reference Scitra-TUN):"
    run_iperf_tcp "Server" "$SCION_MAPPED_IP" "download" "true" "Scitra Download" "$IPERF_PORT"
    run_iperf_tcp "Server" "$SCION_MAPPED_IP" "upload"   "true" "Scitra Upload  " "$IPERF_PORT"
    run_iperf_udp "Server" "$SCION_MAPPED_IP" "10M"      "true" "Scitra Stream  " "$IPERF_PORT"

    echo "3. $CLIENT_RESULT_LABEL:"
    run_iperf_tcp "Client" "$SCION_MAPPED_IP" "download" "true" "$CLIENT_IPERF_PREFIX Download" "$IPERF_PORT"
    run_iperf_tcp "Client" "$SCION_MAPPED_IP" "upload"   "true" "$CLIENT_IPERF_PREFIX Upload  " "$IPERF_PORT"
    run_iperf_udp "Client" "$SCION_MAPPED_IP" "10M"      "true" "$CLIENT_IPERF_PREFIX Stream  " "$IPERF_PORT"
fi

# Cleanup iperf3 server
cleanup_iperf_server

if [[ "$DO_PROFILE" -eq 1 ]]; then
    wait_profiling
    echo ""
    echo -e "\033[1;35m============================================================\033[0m"
    echo -e "\033[1;35m PROFILING ANALYSIS & FLAMEGRAPH\033[0m"
    echo -e "\033[1;35m============================================================\033[0m"
    echo -e "\033[1;32mProfiling-Daten wurden erfolgreich aufgezeichnet:\033[0m"
    echo -e "  - CPU-Profil:     \033[1;34mtestenvironment/.runtime/logs/cpu.prof\033[0m"
    echo -e "  - Top Textreport: \033[1;34mtestenvironment/.runtime/logs/cpu_top.txt\033[0m"
    echo -e "  - Allocs-Profil:  \033[1;34mtestenvironment/.runtime/logs/allocs.prof\033[0m"
    echo ""
    echo -e "\033[1;33mInteraktive Flammengrafik (Flamegraph) im Browser ansehen:\033[0m"
    echo -e "  \033[1;32mgo tool pprof -http=:8085 testenvironment/.runtime/logs/cpu.prof\033[0m"
    echo ""
    echo -e "\033[0;37mDieser Befehl startet einen lokalen Webserver (unter http://localhost:8085/ui/flamegraph),\033[0m"
    echo -e "\033[0;37min dem du millimetergenau die CPU-Verteilung und Funktionsaufrufe analysieren kannst.\033[0m"
    echo -e "\033[1;35m============================================================\033[0m"
fi