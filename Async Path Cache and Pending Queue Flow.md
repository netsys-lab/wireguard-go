# SCION-WireGuard Path Cache and Pending Queue Flow

## Problem

SCION-mapped packets need a valid SCION path before they can be translated and sent.

If no path is cached, the path lookup must not block the normal WireGuard packet processing path. Blocking the TUN reader can delay other packets and can also interfere with the traffic needed to complete the path lookup itself.

## Solution

Path lookup is handled asynchronously.

If a SCION-mapped packet arrives and no valid path is cached, the packet is copied into a pending queue and a background path refresh is triggered.

`RoutineReadFromTUN` continues immediately.

When the path refresh succeeds, the pending packets for that IA pair are flushed and sent through the normal WireGuard outbound pipeline.

## Flow Overview
```
                         ┌────────────────────┐
                         │ Kernel / TUN       │
                         └─────────┬──────────┘
                                   │
                                   v
                         ┌────────────────────┐
                         │ RoutineReadFromTUN │
                         └─────────┬──────────┘
                                   │
                 ┌─────────────────┴─────────────────┐
                 │                                   │
                 v                                   v
        ┌──────────────────┐              ┌────────────────────┐
        │ Normal WG packet │              │ SCION-mapped packet │
        └────────┬─────────┘              └─────────┬──────────┘
                 │                                  │
                 v                                  v
        ┌──────────────────┐              ┌────────────────────┐
        │ Peer lookup      │              │ Path cache lookup   │
        └────────┬─────────┘              └───────┬─────┬──────┘
                 │                                │     │
                 │                         hit    │     │ miss
                 │                                │     │
                 v                                v     v
        ┌──────────────────┐           ┌─────────────┐ ┌────────────────┐
        │ WG outbound pipe │           │ Translate   │ │ Pending queue  │
        └──────────────────┘           └──────┬──────┘ └───────┬────────┘
                                              │                │
                                              v                v
                                      ┌─────────────┐  ┌────────────────┐
                                      │ Peer lookup │  │ RefreshAsync   │
                                      └──────┬──────┘  └───────┬────────┘
                                             │                 │
                                             v                 v
                                      ┌─────────────┐  ┌────────────────┐
                                      │ WG outbound │  │ PathPool cache │
                                      │ pipe        │  │ Replace        │
                                      └─────────────┘  └───────┬────────┘
                                                               │
                                                               v
                                                      ┌────────────────┐
                                                      │ OnPathReady    │
                                                      └───────┬────────┘
                                                              │
                                                              v
                                                      ┌────────────────┐
                                                      │ Pop pending    │
                                                      │ packets        │
                                                      └───────┬────────┘
                                                              │
                                                              v
                                                      ┌────────────────┐
                                                      │ Retry          │
                                                      │ Translate      │
                                                      └───────┬────────┘
                                                              │
                                                              v
                                                      ┌────────────────┐
                                                      │ Peer lookup    │
                                                      └───────┬────────┘
                                                              │
                                                              v
                                                      ┌────────────────┐
                                                      │ WG outbound    │
                                                      │ pipe           │
                                                      └────────────────┘
```


### Flow 1: Normal WireGuard Packet

Packet is read from TUN.
Packet is not SCION-mapped.
Normal WireGuard peer lookup is performed.
Packet enters the normal WireGuard outbound pipeline.

### Flow 2: SCION Packet with Cache Hit

Packet is read from TUN.
Destination is detected as SCION-mapped.
Path cache contains a valid path for the IA pair.
Packet is translated to SCION.
Peer lookup is performed on the translated outer packet.
Packet enters the normal WireGuard outbound pipeline.

### Flow 3: SCION Packet with Cache Miss

Packet is read from TUN.
Destination is detected as SCION-mapped.
No valid path is available in the cache.
Packet is copied into the pending queue for its IA pair.
Async path refresh is started.
RoutineReadFromTUN continues immediately.

### Flow 4: Pending Packet after Path Refresh

Async path refresh succeeds.
PathPool cache is replaced with fresh paths.
OnPathReady(srcIA, dstIA) is called.
Pending packets for that IA pair are flushed.
Packets are translated using the refreshed cache.
Peer lookup is performed.
Packets enter the normal WireGuard outbound pipeline.