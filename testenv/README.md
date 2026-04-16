# SCION-WireGuard Integration Test Environment

## Overview

This test environment provides a modular setup for testing SCION-aware packet translation and forwarding in wireguard-go. It creates a Linux namespace-based topology with Server and Client namespaces connected via WireGuard, with SCION infrastructure for end-to-end testing.

## CRITICAL: Dependency Order

The setup has specific dependencies that MUST be followed in order:

```
1. Generate SCION topology (03a)     → Creates gen/ directory
2. Start Bootstrap server (03b)      → Needs gen/ files
3. Start WireGuard (04)             → Needs bootstrap for SCION config
4. Start SCION services (03c)       → Needs WireGuard interfaces to bind to
```

If you skip steps or run in wrong order, components will fail to start!

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Host Machine                                │
│                                                                     │
│  ┌──────────────────────────┐     ┌──────────────────────────┐      │
│  │      Server Namespace    │     │     Client Namespace     │      │
│  │                          │     │                          │      │
│  │  veth-server (10.0.0.1)  │◄───►│  veth-client (10.0.0.2)  │      │
│  │                          │     │                          │      │
│  │  wg0 (10.10.10.1/24)     │     │  wg0 (10.10.10.2/32)     │      │
│  │                          │     │                          │      │
│  │  wireguard-go (userspace)│     │  wireguard-go (userspace)│      │
│  │                          │     │                          │      │
│  │  Bootstrap Server :8042  │     │                          │      │
│  │  SCION infrastructure    │     │                          │      │
│  │  - sciond                │     │                          │      │
│  │  - dispatcher            │     │                          │      │
│  │  - border router         │     │                          │      │
│  │                          │     │                          │      │
│  │  SCION Echo Server       │     │                          │      │
│  │  (port 30042)            │     │                          │      │
│  └──────────────────────────┘     └──────────────────────────┘      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
testenv/
├── config.sh           # Configuration and shared functions
├── 01-namespaces.sh   # Step 1: Create network namespaces
├── 02-build.sh       # Step 2: Build components
├── 03a-topology.sh   # Step 3a: Generate SCION topology (ONLY GENERATE!)
├── 03b-bootstrap.sh   # Step 3b: Start Bootstrap server
├── 03c-scion.sh      # Step 3c: Start SCION services (needs WireGuard)
├── 03-scion.sh       # Wrapper (shows usage)
├── 04-wireguard.sh   # Step 4: Setup WireGuard (needs bootstrap)
├── 05-echo.sh        # Step 5: Setup SCION echo server
├── 06-test.sh        # Step 6: Run tests
└── testenv.sh       # Master control script
```

## Quick Start

### Full Setup (DOES THIS IN CORRECT ORDER!)

```bash
cd /home/paul/Scintra/wireguard-go/testenv
sudo ./testenv.sh up
```

### Manual Step-by-Step

```bash
cd /home/paul/Scintra/wireguard-go/testenv

# Step 1: Namespaces
sudo ./01-namespaces.sh up

# Step 2: Build
sudo ./02-build.sh build

# Step 3a: Generate topology (NOT start!)
sudo ./03a-topology.sh generate

# Step 3b: Bootstrap server (needs topology)
sudo ./03b-bootstrap.sh up

# Step 4: WireGuard (needs bootstrap)
sudo ./04-wireguard.sh up

# Step 3c: SCION services (needs WireGuard!)
sudo ./03c-scion.sh up

# Step 5: Echo server
sudo ./05-echo.sh up

# Run tests
sudo ./06-test.sh test
```

## Why This Order?

### 1. Generate SCION Topology (03a)
- Creates `gen/` directory with AS configurations
- Does NOT start any services
- Takes ~10 seconds

### 2. Bootstrap Server (03b)
- Needs generated topology files to exist
- Provides SCION certificates to wireguard-go
- Binds to Server namespace underlay IP (10.0.0.1:8042)
- wireguard-go uses `SCION_BOOTSTRAP_URL` to fetch config

### 3. WireGuard (04)
- Starts wireguard-go in both namespaces
- Uses bootstrap URL to fetch SCION configuration
- Creates WireGuard interfaces
- **IMPORTANT**: SCION services need these interfaces to bind to!

### 4. SCION Services (03c)
- Starts sciond, dispatcher, border routers
- These services bind to network interfaces (including WireGuard)
- If WireGuard isn't running, SCION won't start properly
- Needs ~30 seconds to fully initialize

### 5. Echo Server (05)
- Simple UDP echo server for testing return path
- Listens on port 30042 (SCION_UNDERLAY_PORT + 1)

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `verbose` | Log level (silent/verbose/debug) |
| `SCION_DIR` | `/home/paul/Scintra/scion` | SCION directory |
| `SCION_TOPOLOGY` | `topology/tiny-bgp.topo` | Topology file |
| `SCION_UNDERLAY_PORT` | `30041` | SCION UDP port |
| `SCION_LOCAL_IA` | `1-64513` | Local SCION IA |
| `BOOTSTRAP_PORT` | `8042` | Bootstrap server port |

### Network Configuration

- **Server namespace**: 10.0.0.1/24 (veth), 10.10.10.1/24 (WireGuard)
- **Client namespace**: 10.0.0.2/24 (veth), 10.10.10.2/32 (WireGuard)

## Packet Flow

### Forward Path (Client → Server → SCION)

1. Client sends IP packet with SCION-mapped destination (fc00::/8)
2. wireguard-go detects SCION-mapped destination in `send.go`
3. `TranslateEgress` converts IP → encapsulated SCION (IPv6/UDP+SCION)
4. Packet encrypted and sent through WireGuard tunnel
5. Server receives in `receive.go`
6. Detects SCION-mapped destination via `IsSCIONMapped()`
7. Packet sent to dispatcher via `device.dispatcherConn`
8. SCION infrastructure routes packet to destination AS

### Return Path (SCION → Server → Client)

1. SCION infrastructure sends response back
2. `RoutineSCIONIngress` receives SCION packet on listener port
3. `TranslateIngress` converts SCION → IP
4. Peer lookup by destination IP
5. Packet injected into WireGuard tunnel
6. Client receives IP response

## Log Files

All logs are stored in `/tmp/scion-wg-test/`:

| File | Description |
|------|-------------|
| `wg-server.log` | Server wireguard-go output |
| `wg-client.log` | Client wireguard-go output |
| `echo-server.log` | SCION echo server output |
| `bootstrap.log` | Bootstrap server output |
| `scion-start.log` | SCION startup output |

## Troubleshooting

### Problem: SCION topology generation fails

**Solutions**:
```bash
# Clean and regenerate
cd /home/paul/Scintra/scion
./scion.sh topo-clean
sudo /home/paul/Scintra/wireguard-go/testenv/03a-topology.sh generate
```

### Problem: Bootstrap server won't start

**Symptoms**: Port 8042 not listening

**Solutions**:
1. Check topology was generated first
2. Check namespace is running
3. View logs: `tail -f /tmp/scion-wg-test/bootstrap.log`

### Problem: WireGuard can't connect

**Symptoms**: Ping fails, no tunnel

**Solutions**:
1. Check bootstrap is running: `sudo ss -lntp | grep 8042`
2. Check wireguard-go is running: `pgrep -a wireguard-go`
3. View logs: `tail -f /tmp/scion-wg-test/wg-*.log`

### Problem: SCION services won't start

**Symptoms**: Supervisor shows errors

**Solutions**:
1. Check WireGuard is UP first: `sudo ip netns exec Server ip link show wg0`
2. Check topology generated
3. Check bootstrap is running
4. View logs: `tail -f /home/paul/Scintra/scion/logs/*.log`

## Running Tests

```bash
# Run all tests
sudo ./testenv.sh test

# Basic connectivity only
sudo ./06-test.sh basic

# View logs
sudo ./06-test.sh logs

# Check status
sudo ./testenv.sh status
```

## Files Modified

### wireguard-go Changes

- `device/send.go`: Added IPv4 SCION-mapped translation
- `device/device.go`: Added SCION listener and return path handling
- `main.go`: Added SCION_UNDERLAY_PORT environment variable support
- `translator/header_parsing/translate_test.go`: Added unit tests

### New Files Created

- `cmd/scion_echo_server/main.go`: Echo server for return path testing
- `testenv/*.sh`: Modular test environment scripts
- Documentation: This file

## Future Enhancements

1. **Automated ICMP→SCMP translation**: Implement full ICMP to SCMP translation
2. **MTU handling**: Proper fragmentation and path MTU discovery
3. **Multiple AS support**: Test cross-AS SCION routing
4. **Performance testing**: Benchmark translation overhead

## References

- [SCION Documentation](https://docs.scion.org/)
- [wireguard-go](https://git.zx2c4.com/wireguard-go/)
- [SCION Topologies](https://docs.scion.org/en/latest/topo.html)
