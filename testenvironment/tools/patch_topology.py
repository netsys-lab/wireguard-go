#!/usr/bin/env python3
"""Patch the SCION elements that cross Linux network-namespace boundaries.

Source AS (1-64512 by default):
  * expose all BR internal addresses through wg-server
  * expose the SCION daemon through a WireGuard-routable address
  * expose the source Control/Discovery Service through a WireGuard-routable
    address so a bootstrapped translator in the Client namespace does not try
    to connect to a namespace-local 127/8 address

Target AS (3-64534 by default):
  * expose all BR internal addresses and the daemon through the
    Server<->Scitra veth

The rest of the generated local SCION topology remains untouched.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
from pathlib import Path


def split_host_port(value: str) -> tuple[str, str]:
    if value.startswith("["):
        m = re.fullmatch(r"\[(.*)]:(\d+)", value)
        if not m:
            raise ValueError(f"Unsupported address: {value}")
        return m.group(1), m.group(2)
    host, port = value.rsplit(":", 1)
    return host, port


def replace_text(path: Path, old: str, new: str) -> None:
    if not path.exists():
        return
    text = path.read_text()
    if old in text:
        path.write_text(text.replace(old, new))


def daemon_ip_for_as(mapping: dict, asn: str) -> tuple[str, str]:
    matches = [
        (k, v)
        for k, v in mapping.items()
        if k == asn or k.endswith(f"-{asn}") or k.endswith(f":{asn}")
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"Could not uniquely find daemon mapping for AS {asn}: "
            f"{[m[0] for m in matches]}"
        )
    key, value = matches[0]
    value = str(value)
    if value.startswith("["):
        host, _ = split_host_port(value)
    elif value.count(":") == 1 and value.rsplit(":", 1)[1].isdigit():
        host, _ = split_host_port(value)
    else:
        host = value
    return key, host


def patch_br_topology(as_dir: Path, new_ips: list[str]) -> list[tuple[str, str, str]]:
    topo_path = as_dir / "topology.json"
    topo = json.loads(topo_path.read_text())
    brs = topo.get("border_routers", {})
    if not brs:
        raise RuntimeError(f"No border_routers in {topo_path}")
    if len(new_ips) < len(brs):
        raise RuntimeError(f"Need {len(brs)} BR IPs but only got {len(new_ips)}")

    result = []
    for idx, (name, br) in enumerate(sorted(brs.items())):
        old = br.get("internal_addr")
        if not old:
            raise RuntimeError(f"BR {name} has no internal_addr")
        _, port = split_host_port(old)
        new = f"{new_ips[idx]}:{port}"
        br["internal_addr"] = new
        result.append((name, old, new))
    topo_path.write_text(json.dumps(topo, indent=2) + "\n")
    return result


def patch_source_control_service(
    source_dir: Path,
    dispatcher_conf: Path,
    new_ip: str,
) -> tuple[str, str, str]:
    """Expose the source Control/Discovery Service outside the Server namespace.

    In the generated non-Docker topology the CS and DS normally share an
    address such as 127.0.0.44:31000.  That works for processes in the Server
    namespace, but a translator in the Client namespace interprets 127/8 as its
    *own* loopback and therefore receives an immediate RST.

    Patch both topology service entries and the generated dispatcher service
    map to the same WG-routable address.
    """
    topo_path = source_dir / "topology.json"
    topo = json.loads(topo_path.read_text())

    endpoints: list[str] = []
    for key in ("control_service", "discovery_service"):
        services = topo.get(key, {})
        if not services:
            raise RuntimeError(f"No {key} entries in {topo_path}")
        for elem in services.values():
            addr = elem.get("addr")
            if not addr:
                raise RuntimeError(f"{key} entry without addr in {topo_path}")
            endpoints.append(addr)

    # The generated local topology normally uses one shared endpoint for CS/DS.
    # Tolerate multiple entries only if they use the same port; all are moved to
    # the same externally reachable source-control IP.
    ports = {split_host_port(addr)[1] for addr in endpoints}
    if len(ports) != 1:
        raise RuntimeError(
            f"Source Control/Discovery Service uses multiple ports: {sorted(ports)}"
        )
    port = next(iter(ports))
    old_primary = endpoints[0]
    old_host, _ = split_host_port(old_primary)
    new_addr = f"{new_ip}:{port}"

    for key in ("control_service", "discovery_service"):
        for elem in topo[key].values():
            elem["addr"] = new_addr
    topo_path.write_text(json.dumps(topo, indent=2) + "\n")

    # The non-Docker dispatcher config contains entries such as
    #   "1-64512,CS" = "127.0.0.44:31000"
    #   "1-64512,DS" = "127.0.0.44:31000"
    # Keep those consistent with topology.json, otherwise SVC resolution inside
    # the source AS may still target the old loopback endpoint.
    for old_addr in sorted(set(endpoints)):
        replace_text(dispatcher_conf, old_addr, new_addr)

    return old_host, port, new_addr


def source_ips(primary: str, count: int) -> list[str]:
    first = ipaddress.ip_address(primary)
    if first.version != 4:
        raise RuntimeError("V1 expects IPv4 source underlay")
    out = [str(first)]
    # Reserve .2 for WG client and .3 for daemon. Start aliases at .4.
    base = int(first) - (int(first) & 0xFF)
    n = 4
    while len(out) < count:
        out.append(str(ipaddress.ip_address(base + n)))
        n += 1
    return out


def target_ips(first: str, count: int) -> list[str]:
    ip = ipaddress.ip_address(first)
    return [str(ipaddress.ip_address(int(ip) + i)) for i in range(count)]


def shell_array(name: str, values: list[str]) -> str:
    quoted = " ".join(f"'{v}'" for v in values)
    return f"{name}=({quoted})"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--scion-dir", required=True, type=Path)
    p.add_argument("--source-asn", required=True)
    p.add_argument("--target-asn", required=True)
    p.add_argument("--source-br-primary", required=True)
    p.add_argument("--source-daemon-ip", required=True)
    p.add_argument("--source-control-ip", required=True)
    p.add_argument("--target-br-first", required=True)
    p.add_argument("--target-daemon-ip", required=True)
    p.add_argument("--out-env", required=True, type=Path)
    args = p.parse_args()

    source_dir = args.scion_dir / "gen" / f"AS{args.source_asn}"
    target_dir = args.scion_dir / "gen" / f"AS{args.target_asn}"
    daemon_map_path = args.scion_dir / "gen" / "sciond_addresses.json"
    dispatcher_conf = args.scion_dir / "gen" / "dispatcher" / "disp.toml"
    daemon_map = json.loads(daemon_map_path.read_text())

    source_topo = json.loads((source_dir / "topology.json").read_text())
    target_topo = json.loads((target_dir / "topology.json").read_text())
    src_new_ips = source_ips(
        args.source_br_primary, len(source_topo.get("border_routers", {}))
    )
    dst_new_ips = target_ips(
        args.target_br_first, len(target_topo.get("border_routers", {}))
    )

    src_changes = patch_br_topology(source_dir, src_new_ips)
    dst_changes = patch_br_topology(target_dir, dst_new_ips)

    src_old_control_ip, src_control_port, src_control_addr = patch_source_control_service(
        source_dir, dispatcher_conf, args.source_control_ip
    )

    src_key, src_old_daemon = daemon_ip_for_as(daemon_map, args.source_asn)
    dst_key, dst_old_daemon = daemon_ip_for_as(daemon_map, args.target_asn)

    # Keep the existing daemon processes in the Server namespace, only change
    # their API bind addresses so the other namespaces can reach them.
    replace_text(source_dir / "sd.toml", src_old_daemon, args.source_daemon_ip)
    replace_text(target_dir / "sd.toml", dst_old_daemon, args.target_daemon_ip)
    daemon_map[src_key] = args.source_daemon_ip
    daemon_map[dst_key] = args.target_daemon_ip
    daemon_map_path.write_text(json.dumps(daemon_map, indent=2) + "\n")

    args.out_env.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# generated by tools/patch_topology.py",
        shell_array("SOURCE_BR_IPS", src_new_ips),
        shell_array("TARGET_BR_IPS", dst_new_ips),
        f"SOURCE_OLD_DAEMON_IP='{src_old_daemon}'",
        f"TARGET_OLD_DAEMON_IP='{dst_old_daemon}'",
        f"SOURCE_OLD_CONTROL_IP='{src_old_control_ip}'",
        f"SOURCE_CONTROL_IP='{args.source_control_ip}'",
        f"SOURCE_CONTROL_PORT='{src_control_port}'",
        f"SOURCE_CONTROL_ADDR='{src_control_addr}'",
    ]
    args.out_env.write_text("\n".join(lines) + "\n")

    print("Source BR patches:")
    for name, old, new in src_changes:
        print(f"  {name}: {old} -> {new}")
    print(
        f"Source Control/Discovery Service: "
        f"{src_old_control_ip}:{src_control_port} -> {src_control_addr}"
    )
    print(f"Source daemon: {src_old_daemon}:30255 -> {args.source_daemon_ip}:30255")
    print("Target BR patches:")
    for name, old, new in dst_changes:
        print(f"  {name}: {old} -> {new}")
    print(f"Target daemon: {dst_old_daemon}:30255 -> {args.target_daemon_ip}:30255")


if __name__ == "__main__":
    main()
