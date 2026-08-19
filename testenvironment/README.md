# SCION / WireGuard / Scitra Test Environment

## Start

```bash
cd testenvironment
chmod +x testenvironment.bash
sudo ./testenvironment.bash
```

The normal startup builds and verifies the complete infrastructure **without sending a SCION-mapped IPv6 request through our custom translator**.

## Startup order

```text
0  Dependencies / Go / SCION tools

1  Create namespaces + veth links
   ├─ Client
   ├─ Server
   └─ ScitraServer

2  Generate SCION topology
   └─ creates gen/ files needed by SCION and the bootstrap service

3  Refresh wireguard-go build + keys
   ├─ first check wireguard-go/wireguard-go in the project root
   ├─ if present: report it and refresh it with go build
   └─ persistent Go cache means unchanged packages are reused

4  Patch generated SCION addresses
   ├─ source BRs -> addresses that will exist on wg-server
   ├─ source daemon -> reachable Server address
   ├─ target BRs -> Server <-> ScitraServer veth addresses
   └─ target daemon -> 10.30.34.254:30255

5  Start VANILLA wg-server only
   ├─ create wg-server
   ├─ assign 10.0.0.1
   └─ assign all patched source-BR aliases to wg-server

6  Start SCION infrastructure
   ├─ clean stale supervisor state
   ├─ start BRs / control services / daemons
   ├─ require supervisor services RUNNING
   ├─ require source daemon listening
   ├─ require target daemon listening
   └─ WAIT FOR SCION PATH CONVERGENCE
      ├─ poll every 5 seconds
      ├─ allow up to 180 seconds total
      ├─ require control-plane path 3-64534 -> 1-64512
      ├─ require control-plane path 1-64512 -> 3-64534
      ├─ require alive path in both directions
      └─ require two consecutive alive confirmations before continuing

7  Start bootstrap server
   ├─ generated topology already exists
   └─ binds to 10.0.0.1:8042 on wg-server

8  Start and verify TARGET Scitra-TUN in ScitraServer
   ├─ plain IPv4 website 10.30.34.100:8080
   ├─ target daemon reachable
   ├─ bidirectional SCION paths already proven READY in step 6
   ├─ scitra-tun process alive
   ├─ TUN interface "scion" exists + UP
   ├─ expected mapped IPv6 exists
   ├─ fc00::/8 route exists
   ├─ SCION website bound to mapped IPv6:8000
   └─ native SCION ping succeeds

   Then start a SECOND official/reference Scitra-TUN in Server:

      official source Scitra
              ↓
            SCION
              ↓
      official target Scitra
              ↓
        HTTP website :8000
              ↓
          return path

   This reference request must succeed BEFORE our custom wg-client exists.
   The source-side reference Scitra remains running afterwards so the known-good
   path can be used during side-by-side packet debugging.

9  Start our custom wg-client LAST
   ├─ configure WireGuard peer
   ├─ ordinary IPv4 ping to 10.0.0.1 must work
   ├─ real WireGuard handshake must exist
   ├─ bootstrap /topology must be reachable through the WG tunnel
   └─ NO request to fc00::/8 is sent

SETUP READY
```

The actual system under test is deliberately not called during startup:

```text
Client IPv6
  -> OUR translator
  -> WireGuard
  -> SCION
  -> target Scitra-TUN
  -> SCION website
```

Run that only with:

```bash
sudo ./testenvironment.bash test
```


## Reach the SCION website

Get the target mapped IPv6:

```bash
TARGET="$(cat .runtime/state/website-ip.txt)"
```

Known-good path using the source/reference Scitra-TUN:

```bash
sudo ip netns exec Server \
  curl -g -6 -v "http://[$TARGET]:8000/"
```

Actual custom-translator path:

```bash
sudo ip netns exec Client \
  curl -g -6 -v "http://[$TARGET]:8000/"
```

The first command should remain usable for the entire lifetime of the environment and acts as the reference baseline.

## Packet debugging

See [`DEBUGGING.md`](DEBUGGING.md) for the full side-by-side debugging plan, including:

- which namespace/interface to capture in Wireshark/tcpdump;
- reference Scitra capture commands;
- custom translator/WireGuard capture commands;
- target Scitra health commands;
- the stage-by-stage failure-localization flow.

## SCION path convergence

A freshly started multi-AS topology may report `no path found` for a while even though all supervisor services and daemons are already running. The setup therefore does not fail on the first lookup anymore.

Default readiness policy:

```text
poll interval:         5 seconds
maximum wait:          180 seconds
query timeout:         8 seconds per showpaths command
stable confirmations:  2 consecutive rounds
```

The setup first waits for control-plane paths (`showpaths --refresh --no-probe`) in both directions and then requires probed `Status: alive` paths in both directions twice in a row. It continues immediately once this condition is met; it does not always sleep for the full three minutes.

Override examples:

```bash
sudo SCION_PATH_READY_TIMEOUT=240 ./testenvironment.bash
sudo SCION_PATH_READY_INTERVAL=10 ./testenvironment.bash
```

Detailed attempts are written to:

```text
.runtime/logs/scion-path-target-to-source.log
.runtime/logs/scion-path-source-to-target.log
```

## Why the second Scitra-TUN stays running

The target Scitra-TUN remains running in `ScitraServer` because it is the server-side translator under test infrastructure.

The second source-side Scitra-TUN is a **known-good reference client**. It runs in the `Server` namespace, proves that official Scitra can reach the target Scitra website through the SCION topology and receive the response, and then remains running until the environment is stopped.

It does not interfere with the custom client because the custom client runs in the separate `Client` namespace. Keeping the reference Scitra alive makes it possible to compare a known-good official-Scitra packet path with the custom translator at any time.

## Target ScitraServer interfaces

Before Scitra starts:

```text
ScitraServer
├─ lo
└─ veth-scitra   10.30.34.100/24
```

`veth-scitra` is the public/SCION-underlay side. Scitra-TUN creates the application-side TUN itself:

```text
ScitraServer
├─ lo
├─ veth-scitra   10.30.34.100/24
└─ scion         <SCION-mapped IPv6>
                  └─ fc00::/8 route
```

Target Scitra is only considered READY when the process, TUN, mapped IPv6, route and SCION connectivity checks all succeed.

## wireguard-go project-root build

The setup explicitly checks:

```text
<project-root>/wireguard-go
```

If the binary already exists:

```text
[OK] Existing wireguard-go binary found in project root: .../wireguard-go
[INFO] Refreshing it with 'go build' ...
```

It does **not** blindly trust the old binary. `go build` is executed again so it matches the current source, but the persistent caches in:

```text
testenvironment/.deps/go-build-cache
testenvironment/.deps/go-mod-cache
```

are reused. Therefore unchanged Go packages are not rebuilt from scratch.

## Websites

Plain infrastructure health endpoint:

```text
http://10.30.34.100:8080/
```

SCION endpoint:

```text
3-64534,10.30.34.100
 -> scion2ip
 -> mapped IPv6
 -> TCP/8000
```

## Commands

```bash
sudo ./testenvironment.bash
sudo ./testenvironment.bash status
sudo ./testenvironment.bash test
sudo ./testenvironment.bash down
sudo ./testenvironment.bash clean
sudo ./testenvironment.bash purge
sudo ./testenvironment.bash uninstall
```

## Important logs

```text
.runtime/logs/
├── wireguard-build.log
├── wg-server.log
├── wg-client.log
├── scion-start.log
├── bootstrap.log
├── plain-website.log
├── scion-website.log
├── scitra-tun.log
├── scion-path-target-to-source.log
├── scion-path-source-to-target.log
├── scion-reference-ping.log
├── reference-source-scitra.log
├── reference-scion-http.html
├── reference-scion-http.stderr
└── curl-e2e.stderr
```

## Source Control Service across namespaces

For the source AS, the generated non-Docker topology normally advertises its
Control/Discovery Service on a loopback address such as `127.0.0.44:31000`.
That address cannot be used by the translator in the separate `Client`
namespace. During step 4 the testenvironment therefore patches the advertised
source Control/Discovery Service to `10.0.0.6:<generated-port>`, updates the
SCION dispatcher service map, and step 5 places `10.0.0.6/32` on `wg-server`.
Startup verifies both that SCION binds the patched endpoint and that `Client`
can reach it through WireGuard before declaring the custom client ready.
