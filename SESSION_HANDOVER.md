# Session Handover — SCION translation data path

Branch: `fix/scion-translation-data-path` (working tree, **nothing committed**)
Baseline commit: `65f850b` "[Fix] derive data ports from L4 and use dispatcher port for SCMP"

## What this session changed

### 1. Ingress is now always-IPv6 (Scitra-conformant) — `translator/header_parsing/translate.go`

`TranslateIngress` was rewritten so the reconstructed application packet is **always IPv6**:

- `src` = canonical SCION-mapped IPv6 of the remote endpoint
- `dst` = local VPN/TUN IPv6 of this translator instance (param or `WGSrcIPv6()` fallback)

Removed the old `islocal`/`forceIPv6`/family branches and the whole destination-address
reconstruction. The IPv4-rebuild branch in `TranslateIngress` is now unreachable and is
marked `OUTDATED` dead code (kept for rollback reference only).

New helper `mapSCIONHostToIPv6(ia, addrType, raw)`:
- `T4Ip` → `ScionToIP(isd, asn, 0, 0, ip, 8)` (embeds IPv4 behind `::ffff:`)
- `T16Ip` already in `fc00::/8` → returned as-is
- `T16Ip` bare interface id (e.g. `::1`) → `ScionToIP(isd, asn, 0, 0, ip, 8)`
- other → error

### 2. `device/receive.go`

`RoutineSequentialReceiver` resolves the local TUN IPv6 once per batch
(`device.translator.WGSrcIPv6()`) and passes it explicitly to `TranslateIngress(...,
ingressTunIP)` instead of `nil` (mirrors Scitra's `translateIngress` call). `TranslateIngress`
still falls back to `WGSrcIPv6()` internally when given `nil`.

### 3. Egress SCION host format fix — `TranslateEgress`

`TranslateEgress` now carries the **full SCION-mapped IPv6** as the SCION `T16Ip` destination
host instead of the bare low-64 interface id (`::X`). The IPv4 case is unchanged (SCION `T4Ip`
raw IPv4). This matches the reference Python generators in `translator/data/*.py`
(e.g. `translate_udp_ipv6.py` sets `dst_host = "fc00:20fb:f100::2"`).

## Tests

- **New** `TestMapSCIONHostToIPv6` — T4Ip, T16Ip-already-mapped, T16Ip-interface, unsupported-type cases.
- **Fixed** `TestICMPTypeCodeMapping` / `TestSCMPTypeCodeMapping` — test-literal bug:
  `layers.ICMPv6TypeCode` packs the **Type in the high byte** (confirmed from gopacket v1.3.1
  `layers/icmp6.go`). Literals must be built with `layers.CreateICMPv6TypeCode(type, code)`,
  not by casting the bare `ICMPv6Type*` constant.
- **Fixed 7 pre-existing failures** (all had failed at baseline):
  - `TestTranslateIpUdpToScion4Local` / `TestTranslateIpUdpToScion6Local` — added
    `SetDispatchedPorts(DispatchPortRange{32760,32770,true})`; the same-AS fixture expects the
    outer UDP dst port to equal the inner L4 dst port (32767), which `chooseSameASDispatchPort`
    only selects when inside the configured dispatched range.
  - `TestTranslateIpUdpToScion6{,Local}` — added `SetConfiguredIPv6(fc00:10fb:f000::1)`; the
    IPv6-underlay branch requires a resolvable source via `WGSrcIPv6()`.
  - `TestTranslateIcmpToScmp` / `TestICMPv6ToSCMP` / `TestMTU_Translation` — switched the path
    callback from empty `path.Path{}` (no next-hop → error for inter-AS dst) to `loadTestPath(t,0)`.
  - `TestTranslateIngressUDPNonSCIONDocumentsAmbiguity` — build the translator via
    `NewTranslator(...)` (bare `&Translator{}` leaves `t.log` nil → panic).

All `translator/...`, `device/...`, and `flow/...` tests pass. `go build ./...` passes.

## Decisions & reasoning (outcomes)

1. **Always-IPv6 ingress.** Same-AS vs inter-AS must only affect SCION path/next-hop, never the
   application-side IP version. Validated by round-trip identity: ingress `src` now equals the
   egress fixture's app-layer src. `TestTranslateScion6ToIpUdp` and
   `TestTranslateScion6ToIpUdpLocal` went from failing → passing.
2. **Egress host format.** Discovered via fixture dump + the Python generators that the SCION
   header carries the full `fc00::` host for interface-style addresses (T16Ip), but raw IPv4 for
   IPv4-mapped ones (T4Ip). The previous Go code unmapped both to the bare host, producing `::2`
   on the wire — a mismatch with the reference. Fix keeps the mapped address as-is for T16Ip.
3. **Dispatch-port fixture mismatch** (`30041` vs `32767`) is not a regression from this work —
   it stems from `chooseSameASDispatchPort` gating on the configured dispatched range. The tests
   now configure a range covering the fixture port; a real deployed value comes from the SCION
   topology (`device/scion_config.go` `loadDispatchedPortsFromTopology`).
4. **`gofmt` on CRLF files is a trap.** `gofmt -w` on files committed with CRLF line endings
   rewrites every line (whole-file diff, merge-conflict noise). Do NOT run `gofmt -w` on the
   remaining CRLF files as part of feature work; convert line endings or relax the format test
   separately.

## Still to be done / open items

- **`TestFormatting` still fails** on exactly 3 CRLF files: `device/device.go`,
  `device/send.go`, `device/scion_pending_flush.go`. `format_test.go` only strips CRLF on
  Windows (`runtime.GOOS == "windows"`). Options: (a) convert those files to LF, or (b) make
  `format_test.go` normalize CRLF on all platforms. Note `device/device.go` already has a real
  unstaged content change (see below), so fix its line endings together with that.
- **Working tree has unstaged formatting/content edits outside this session's scope** that still
  need review and a decision to keep/commit: `device/device.go`, `device/scion_flow_state.go`,
  `scionlog/log_test.go`, `translator/pathpolicy/{filter,policy,policy_test}.go`,
  `translator/pathpool/{pathpool,pathpool_refresh}.go`, and `vm-wg-mdbootstrap-setup.md`
  (a markdown edit). Verify these match the author's intent before committing.
- **Nothing is committed yet** on this branch; the 3 functional files
  (`device/receive.go`, `translator/header_parsing/translate.go`,
  `translator/header_parsing/translate_test.go`) plus the formatting files are all unstaged.
  Suggest splitting the CRLF/formatting fixes into a separate commit from the data-path change.
- **Dead code to consider removing later:** the `OUTDATED` IPv4-rebuild branch inside
  `TranslateIngress` (kept for rollback context).
- **Skipped placeholder tests** (`TestTranslateScmpToIcmp`, `TestRespondPacketTooBig`, etc.)
  still `t.Skip` and need real SCMP fixtures.
- Test comment references **Work Package 10 "TranslateIngress disposition refactor"** as the
  eventual home for the non-SCION-UDP pass-through/error ambiguity documented in
  `TestTranslateIngressUDPNonSCIONDocumentsAmbiguity`.

## Key reference values (fixture-derived)

- `mapSCIONHostToIPv6(1-64496, T4Ip, 10.0.0.1)` → `fc00:10fb:f000::ffff:a00:1`
- `mapSCIONHostToIPv6(1-64496, T16Ip, ::1)` → `fc00:10fb:f000::1`
- IPv6-underlay fixture outer header: src `fc00:10fb:f000::1`, dst `::1`, udp 32766→31002
- Same-AS fixtures: outer dst port = inner L4 dst port (32767), dispatched range must cover it
