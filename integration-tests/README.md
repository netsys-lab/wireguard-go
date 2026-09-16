# Integration Test Suite

This directory contains the automated integration tests for the WireGuard-to-SCION translation layer.

## How to Run

To run the entire test suite, ensure your test environment is running (`sudo ./testenvironment.bash up`), then execute:

```bash
sudo ./run_all.sh
```

## Why and How We Test

Our integration tests follow a black-box approach: we execute standard networking tools (like `ping`, `curl`, `nc`) inside the isolated `Client` network namespace. The tools generate standard IP traffic, which our custom `wireguard-go` intercepts, translates to SCION, and sends through a local SCION test network.

By relying on the exit codes of these standard Linux tools (where `0` means success), we can automatically verify if our translation layer successfully mapped the traffic.

### The Tests

1. **`01_ping.sh` (ICMP)**
   - **Why:** To verify basic network reachability and ICMP translation.
   - **How:** Runs `ping -c 3` against the mapped SCION target.
   - **Note:** SCMP (SCION Control Message Protocol) encodes the underlay port in the ICMP ID field. If this test fails, it usually indicates the translator does not correctly map the ICMP ID back and forth.

2. **`02_tcp_http.sh` (Small TCP Payload)**
   - **Why:** To verify that standard TCP handshakes (SYN, SYN-ACK, ACK) and small data payloads work.
   - **How:** Runs `curl --fail` to fetch a small HTTP webpage. It succeeds if a HTTP 200 response is received.

3. **`03_tcp_large.sh` (Large TCP Payload & MTU)**
   - **Why:** To verify that the translator correctly handles Path MTU (Maximum Transmission Unit) differences. SCION packets have larger headers than IPv4/IPv6 packets, meaning the available payload size is smaller.
   - **How:** Runs an `iperf3` speedtest transferring 1MB of data. If the translator fails to clamp the TCP MSS (Maximum Segment Size) or fragment packets correctly, the large packets will be dropped and this test will stall/fail.

4. **`04_udp_echo.sh` (UDP)**
   - **Why:** To verify that connectionless UDP traffic is translated correctly.
   - **How:** Starts a `nc -u -l` (Netcat) server on the target and sends a text string via `nc -u` from the client. It succeeds if the exact string is received on the other side.

5. **`05_failover.sh` (SCION Path Failover)**
   - **Why:** To verify that our translator can dynamically adapt if a SCION network path goes down.
   - **How:** Uses the SCION supervisor tool to deliberately terminate one of the SCION border routers in the test topology. It then checks if traffic (via `ping`) still reaches the destination by falling back to an alternate path.
