# Integration Test Suite

This suite verifies the WireGuard-to-SCION translation layer using black-box network testing across isolated Linux network namespaces (`Client` and `ScitraServer`).

## How to Run

Ensure the test topology is up, then run the full suite:

```bash
sudo ./testenvironment.bash up
sudo ./run_all.sh
```

---

## Architecture & Test Rationales

Standard network tools (`ping`, `curl`, `nc`, `iperf3`) run inside the `Client` namespace. Traffic is intercepted by `wireguard-go`, translated into SCION packets, forwarded across the local SCION topology, and returned via `ScitraServer`.

| Test Script | Focus Area | Protocol Verification |
| :--- | :--- | :--- |
| `01_ping.sh` | Basic Connectivity | Validates ICMP reachability and SCMP/ICMP ID mapping. |
| `02_tcp_http.sh` | TCP Handshake | Validates three-way handshake (`SYN`, `SYN-ACK`, `ACK`) and small HTTP payloads. |
| `03_tcp_throughput.sh` | PMTUD & Throughput | Validates dynamic Path MTU Discovery and MSS translation under bulk transfer. |
| `04_udp_echo.sh` | Datagram Translation | Validates connectionless UDP encapsulation and payload integrity. |
| `05_mtu_fragmentation.sh` | IP Layer Fragmentation | Validates IP fragmentation handling when payloads exceed tunnel MTU. |
| `06_concurrent_streams.sh` | NAT Table Concurrency | Validates concurrent connection tracking, multiplexing, and state locking. |
| `07_failover.sh` | Dynamic Path Rerouting | Validates automatic failover to alternative SCION paths upon border router loss. |

---

## Design Decisions & Pitfalls Addressed

### 1. Dynamic PMTUD vs. MSS Handshake Clamping (`03_tcp_throughput.sh`)
* **The Issue:** If the client tunnel interface MTU is configured to a conservative value (e.g., `1280` or `1420`), TCP sets its MSS to that threshold at connection startup. This bypasses runtime Path MTU Discovery entirely.
* **Design Decision:** The test ensures the client MTU is larger than the underlying SCION path capacity (accounting for SCION's larger, variable-length headers). This forces the translation layer to handle packets exceeding path capacity and signal ICMP/SCMP "Packet Too Big" back to the client stack.

### 2. UDP Echo Race Conditions & File Caching (`04_udp_echo.sh`)
* **The Issue:** Standard OpenBSD `netcat` in UDP listen mode (`nc -u -l`) does not cleanly exit and suffers from stdio buffer delays. Additionally, leftover test artifacts from prior runs could yield false positives on subsequent runs.
* **Design Decision:** Temporary verification files are wiped before execution and monitored via explicit exit traps. Socket reads are forced to flush before asserting payload equality.

### 3. Enforcing IP-Level UDP Fragmentation (`05_mtu_fragmentation.sh`)
* **The Issue:** UDP lacks Layer 4 segmentation. A 1450-byte UDP payload (`1478` bytes with IP/UDP headers) only fragments if the local interface MTU is $\le 1420$ bytes. If the interface defaults to 1500 bytes, no fragmentation occurs and the test passes without testing the translator's fragmentation pipeline.
* **Design Decision:** The test explicitly verifies that the client interface MTU is configured $\le 1420$ bytes before transmitting, preventing invalid runs.

### 4. Concurrency & State Churn (`06_concurrent_streams.sh`)
* **What is it?**: Translating between plain IP and SCION requires a stateful NAT (Network Address Translation) table. Because SCION addresses don't map 1:1 to IPv4/IPv6, the translator must multiplex multiple TCP/UDP flows over the same SCION tunnels by dynamically mapping ports. 
* **The Issue:** A naive NAT table might work for a single connection but fail under load. "NAT table concurrency" refers to the ability of the translator to safely handle multiple packets arriving at the exact same time that need to update or read the state table. If the code isn't thread-safe (e.g. missing mutex locks), it will crash or corrupt connections. "Port multiplexing" is the ability to assign unique ports to outgoing traffic and reliably map incoming traffic back to the correct original socket.
* **Design Decision:** The test elevates the `iperf3` parallel stream count (`-P 8`) and payload size (`-n 1M`). This fires 8 simultaneous, heavy TCP streams through the translator. By doing this, we aggressively stress the concurrent read/write state locks of the NAT table. It verifies that port multiplexing correctly isolates the 8 streams from each other without cross-talk, and that the state table doesn't leak memory or exhaust ports during rapid connection creation and teardown.

### 5. Topology State Preservation on Failure (`07_failover.sh`)
* **The Issue:** If `set -e` aborts execution after terminating a border router, the router remains stopped, corrupting subsequent test runs.
* **Design Decision:** Router restoration is bound to a Bash `EXIT` trap, guaranteeing that the SCION topology returns to an operational state regardless of whether the test passes, fails, or is interrupted.
