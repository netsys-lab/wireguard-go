# SCION-Extended Go Implementation of [WireGuard](https://www.wireguard.com/)

This repository contains a modified version of the official `wireguard-go` implementation, extended with a custom translation layer for the [SCION](https://www.scion.org/) next-generation internet architecture.

Our implementation modifies the standard WireGuard client to act as a translator for SCION networks. It allows WireGuard traffic to be routed over a SCION topology. Specifically, the extended `wg-client` maps traffic (such as mapped IPv6 requests) and handles the translation required to establish secure WireGuard tunnels seamlessly across SCION paths.

## Test Environment & Sandbox

To help build, deploy, and verify our translation layer without invasive system-wide changes, we provide a complete, namespace-isolated test sandbox (`ip netns`). It simulates a full topology including a client, server, and the underlying SCION infrastructure.

 **For prerequisites, startup sequences, and debugging guides, please refer to our [Test Environment README](testenvironment/README.md).**

---

## Usage (SCION)

### **Build the extended binary** (Requires Go >= 1.24):
```bash
make
```

### Start the client with SCION enabled:
Export the required SCION configuration paths and enable the extension before running wireguard-go.
```bash
export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
export SCION_ENABLED=true
export SCION_CONFIG_DIR="/path/to/scion/etc"
export SCION_BOOTSTRAP_URL="http://<bootstrap-ip>:<port>"
export SCION_UNDERLAY_PORT="30041"
# export SCION_POLICY_FILE="/path/to/policy" # Optional
export LOG_LEVEL="debug"

./wireguard-go --foreground wg0
```

### Configure the WireGuard interface:
Once the UAPI socket is ready, configure your keys and endpoints using standard wg(8) tools. Ensure you allow the SCION-mapped IPv6 range.
```bash
wg set wg0 private-key /path/to/client_private \
           peer <SERVER_PUBLIC_KEY> \
           endpoint <WG_ENDPOINT> \
           allowed-ips 0.0.0.0/0, ::/0 \
           persistent-keepalive 25
```

### Configure IPs and Routing:
Assign your tunnel addresses, bring the interface up, and explicitly route the SCION-mapped IPv6 prefix (e.g., fc00::/8) into the wg0 device so the translator can intercept it.
```bash
ip addr add <CLIENT_IP>/32 dev wg0
ip -6 addr add <CLIENT_IPV6>/128 dev wg0
ip link set wg0 up
ip -6 route add fc00::/8 dev wg0
```


# Legacy Wireguard-go Standalone

*Note: Our fork preserves all the original functionality of the upstream wireguard-go project. The standard, non-SCION features still work exactly as expected. The following sections contain the official upstream usage instructions for reference.*

## Usage

Most Linux kernel WireGuard users are used to adding an interface with `ip link add wg0 type wireguard`. With wireguard-go, instead simply run:

```
$ wireguard-go wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run wireguard-go without forking to the background, pass `-f` or `--foreground`:

```
$ wireguard-go -f wg0
```

When an interface is running, you may use [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Platforms

### Linux

This will run on Linux; however you should instead use the kernel module, which is faster and better integrated into the OS. See the [installation page](https://www.wireguard.com/install/) for instructions.

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

### Windows

This runs on Windows, but you should instead use it from the more [fully featured Windows app](https://git.zx2c4.com/wireguard-windows/about/), which uses this as a module.

### FreeBSD

This will run on FreeBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_USER_COOKIE`.

### OpenBSD

This will run on OpenBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_RTABLE`. Since the tun driver cannot have arbitrary interface names, you must either use `tun[0-9]+` for an explicit interface name or `tun` to have the program select one for you. If you choose `tun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

## Building

This requires an installation of the latest version of [Go](https://go.dev/).

```
$ git clone https://git.zx2c4.com/wireguard-go
$ cd wireguard-go
$ make
```

## License

    Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
