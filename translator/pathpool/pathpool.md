# PathPool Documentation

## Purpose

`PathPool` is the SCION path cache used by the WireGuard/SCION translator.
It stores paths per source/destination IA pair and returns usable cached paths immediately.
Network path retrieval happens asynchronously, so packet processing does not block while paths are fetched.

## Files

- `pathpool.go` contains the core cache data structures and cache lookup logic.
- `pathpool_refresh.go` contains asynchronous refresh, startup prefetch, periodic refresh, and refresh callback logic.
- `snapshot.go` contains read-only JSON-safe DTOs for exposing the current path cache and selection state to JNI/UI/debug code.
- `pathpool_test.go` contains unit tests using mocked path retrievers and mock paths.
- `pathpool_integration_test.go` contains optional integration tests against a real SCION daemon/test environment.

## Core Behavior

### Cache hit

When `Get(ctx, src, dst)` is called and valid paths are already cached:

1. Expired paths are removed lazily.
2. Valid paths are returned immediately.
3. If the paths are close to expiry, an async refresh is scheduled in the background.

The caller can continue translating and sending the packet without waiting for a network path query.

### Cache miss

When `Get(ctx, src, dst)` is called and no valid path is cached:

1. The IA pair is remembered as a known pair.
2. `RefreshAsync(src, dst, "cache-miss")` is scheduled.
3. `Get` returns `ErrPathPending` immediately.

The caller should treat `ErrPathPending` as a temporary state and queue the packet for retry after refresh.

### Async refresh

`RefreshAsync` only schedules the refresh. It does not fetch paths itself.

It:

1. remembers the IA pair,
2. checks whether a refresh is already in flight,
3. marks the pair as in flight,
4. starts `refreshWorker` in a goroutine.

`refreshWorker` performs the actual path fetch through the configured `PathRetriever`.
On success, it replaces the cached paths for the IA pair and calls the refresh callback.
On failure, it stores the error in `lastError` and clears the in-flight state.

## Refresh Sources

Paths can be refreshed from four places:

1. **Startup prefetch** through `PrefetchAsync` for configured/common IA pairs.
2. **Cache miss** through `Get`, which schedules `RefreshAsync(..., "cache-miss")`.
3. **Expiry soon** through `Get`, which returns valid paths and schedules `RefreshAsync(..., "expiry-soon")` if paths are near expiry.
4. **Periodic timer** through `refreshLoop`, which calls `RefreshKnownPairs("timer")`.

## Replacement Semantics

Async refresh replaces the cached paths for an IA pair.
It does not append to the old path list.

This avoids mixing fresh paths with expired, stale, or no longer preferred paths.

`Add` still appends paths and is mainly useful for tests or manual insertion.

## Known IA Pairs

The `known` map tracks IA pairs that the pool has seen before.
Pairs become known when they are:

- requested through `Get`,
- inserted through `Add`,
- configured through `PrefetchAsync`.

The periodic timer only refreshes known pairs.
The pool cannot prefetch “all paths” by itself because it does not know every possible destination IA.

## In-Flight Deduplication

The `inflight` map prevents duplicate refreshes for the same IA pair.
If multiple packets miss the same cache entry at the same time, only one network path query is started.
Later refresh requests for the same IA pair are skipped while the first refresh is still running.

## Callback

`SetRefreshCallback` registers a callback that is executed after a successful refresh.
The device layer uses this callback as `OnPathReady(src, dst)` to flush pending packets for that IA pair.

The callback is called after the PathPool lock has been released.

## Snapshot / UI Status

`snapshot.go` exposes a read-only view of the cache.
It converts internal path data into JSON-safe DTOs containing:

- IA pairs,
- number of available paths,
- selected path fingerprint,
- path next hop,
- expiry,
- MTU,
- interfaces/hops,
- refresh state,
- last refresh error.

This is intended for debugging and for future JNI/frontend status display.

## Expected Caller Behavior

Callers should handle `ErrPathPending` specially:

```go
paths, err := pathPool.Get(ctx, src, dst)
if errors.Is(err, pathpool.ErrPathPending) {
    // queue packet and wait for OnPathReady
}
```

Other errors should be treated as real failures.

- - -
_AI-assisted documentation draft and formatting using ChatGPT, GPT-5.5 Thinking.  
Created: 2026-05-16. Reviewed and adapted by project contributors._