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
IPERF_DURATION=5

ITERATIONS=10

echo "============================================================"
echo " UNIFIED SCION TRANSLATOR BENCHMARK & DIAGNOSTIC SUITE"
echo " Target: Custom Go Translator vs Reference Scitra-TUN"
echo "============================================================"

# --- CLEANUP TRAP ---
cleanup() {
    sudo ip netns exec ScitraServer pkill -f "iperf3.*${IPERF_PORT}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

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
measure_latency "Server" "$SCION_MAPPED_URL" "Baseline B (Reference Scitra-TUN)"
measure_latency "Client" "$SCION_MAPPED_URL" "Target (Custom Go Translator)"

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
measure_throughput "Server" "$SCION_MAPPED_URL" "Baseline B (Reference Scitra-TUN)"
measure_throughput "Client" "$SCION_MAPPED_URL" "Target (Custom Go Translator)"

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
run_load_test "Server" "$SCION_MAPPED_URL" "Baseline B (Reference Scitra-TUN)"
run_load_test "Client" "$SCION_MAPPED_URL" "Target (Custom Go Translator)"

# --- 4. L4 TRANSPORT & PACKET LOSS DIAGNOSTICS (iperf3) ---
echo ""
echo "--- [4/4] L4 Transport Layer Diagnostics (iperf3 on mapped Port 8000) ---"

# 1. Temporarily pause python http.server on port 8000
sudo ip netns exec ScitraServer pkill -f "python3.*8000" 2>/dev/null || true
sleep 1

# 2. Start iperf3 server on port 8000 (bind to mapped IPv6 and IPv4)
sudo ip netns exec ScitraServer pkill -f "iperf3.*8000" 2>/dev/null || true
sleep 1
sudo ip netns exec ScitraServer iperf3 -s -p 8000 -D
sleep 1

# Function to restore python server when iperf finishes
restore_http_server() {
    sudo ip netns exec ScitraServer pkill -f "iperf3.*8000" 2>/dev/null || true
    sudo ip netns exec ScitraServer python3 -m http.server 8000 \
        --bind fc00:30fc:1600::ffff:a1e:2264 \
        --directory "$SCION_DOCROOT" >/dev/null 2>&1 &
}

run_iperf_tcp() {
    local netns="$1"
    local target_ip="$2"
    local mode="$3"
    local is_v6="$4"
    local label="$5"

    local v6_arg=""
    if [ "$is_v6" = "true" ]; then v6_arg="-6"; fi

    local r_arg=""
    if [ "$mode" = "download" ]; then r_arg="-R"; fi

    echo -n "  [TCP $mode] ${label}... "

    local json_output
    json_output=$(sudo ip netns exec "$netns" iperf3 $v6_arg -c "$target_ip" -p 8000 \
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

    local v6_arg=""
    if [ "$is_v6" = "true" ]; then v6_arg="-6"; fi

    echo -n "  [UDP @ $target_bw] ${label}... "

    local json_output
    json_output=$(sudo ip netns exec "$netns" iperf3 $v6_arg -c "$target_ip" -p 8000 \
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
run_iperf_tcp "Server" "$TARGET_IP" "download" "false" "Plain IP Download"
run_iperf_tcp "Server" "$TARGET_IP" "upload"   "false" "Plain IP Upload  "
run_iperf_udp "Server" "$TARGET_IP" "30M"      "false" "Plain IP Stream  "

echo "2. Baseline B (Reference Scitra-TUN):"
run_iperf_tcp "Server" "$SCION_MAPPED_IP" "download" "true" "Scitra Download"
run_iperf_tcp "Server" "$SCION_MAPPED_IP" "upload"   "true" "Scitra Upload  "
run_iperf_udp "Server" "$SCION_MAPPED_IP" "10M"      "true" "Scitra Stream  "

echo "3. Target (Custom Go Translator):"
run_iperf_tcp "Client" "$SCION_MAPPED_IP" "download" "true" "Go Trans Download"
run_iperf_tcp "Client" "$SCION_MAPPED_IP" "upload"   "true" "Go Trans Upload  "
run_iperf_udp "Client" "$SCION_MAPPED_IP" "10M"      "true" "Go Trans Stream  "

# Restore HTTP server on port 8000
restore_http_server