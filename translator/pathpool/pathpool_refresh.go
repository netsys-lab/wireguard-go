package pathpool

import (
	"context"
	"log"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

// SetRefreshCallback registers a callback that is called after a successful
// async path refresh. The Device uses this to flush pending packets once fresh
// paths are available.
func (pp *PathPool) SetRefreshCallback(cb RefreshCallback) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	pp.onRefresh = cb
	log.Printf("[PATHPOOL] refresh callback registered")
}

// PrefetchAsync starts async refreshes for configured IA pairs during startup.
// It is used to warm the path cache before the first packet for a known
// destination arrives.
func (pp *PathPool) PrefetchAsync(pairs []IAPair) {
	if len(pairs) == 0 {
		log.Printf("[PATHPOOL] PrefetchAsync: no pairs configured")
		return
	}

	log.Printf("[PATHPOOL] PrefetchAsync: pairs=%d", len(pairs))

	for _, pair := range pairs {
		pp.RefreshAsync(pair.Src, pair.Dst, "startup-prefetch")
	}
}

// RefreshAsync schedules a non-blocking path refresh for a src/dst IA pair.
// It remembers the IA pair, prevents duplicate in-flight refreshes, and starts
// a background worker if no refresh is currently running.
func (pp *PathPool) RefreshAsync(src, dst addr.IA, reason string) {
	k := key{src: src, dst: dst}

	pp.mu.Lock()

	pp.known[k] = struct{}{}

	if pp.retriever == nil {
		log.Printf("[PATHPOOL] RefreshAsync skipped: retriever nil src=%s dst=%s reason=%s", src, dst, reason)
		pp.mu.Unlock()
		return
	}

	if pp.inflight[k] {
		log.Printf("[PATHPOOL] RefreshAsync skipped: already inflight src=%s dst=%s reason=%s", src, dst, reason)
		pp.mu.Unlock()
		return
	}

	pp.inflight[k] = true
	pp.mu.Unlock()

	go pp.refreshWorker(src, dst, reason)
}

// refreshWorker performs the actual path fetch in the background.
// It calls the retriever, updates the cache or lastError state, clears the
// in-flight flag, and calls the refresh callback after a successful update.
func (pp *PathPool) refreshWorker(src, dst addr.IA, reason string) {
	k := key{src: src, dst: dst}

	log.Printf("[PATHPOOL] Refresh start: src=%s dst=%s reason=%s", src, dst, reason)

	ctx, cancel := context.WithTimeout(context.Background(), pp.queryTimeout)
	defer cancel()

	paths, err := pp.retriever.RetrievePaths(ctx, src, dst)

	var cb RefreshCallback
	var shouldCallCallback bool
	var pathCount int

	pp.mu.Lock()

	entry, ok := pp.cache[k]
	if !ok {
		entry = &pathsEntry{}
		pp.cache[k] = entry
	}

	if err != nil {
		entry.lastError = err
		pp.inflight[k] = false
		pp.mu.Unlock()

		log.Printf("[PATHPOOL] Refresh failed: src=%s dst=%s reason=%s err=%v", src, dst, reason, err)
		return
	}

	if len(paths) == 0 {
		entry.lastError = ErrNoPaths
		pp.inflight[k] = false
		pp.mu.Unlock()

		log.Printf("[PATHPOOL] Refresh returned no paths: src=%s dst=%s reason=%s", src, dst, reason)
		return
	}

	// Replace old paths instead of appending.
	// This avoids keeping stale or expired paths mixed with fresh ones.
	entry.paths = entry.paths[:0]

	for _, p := range paths {
		wrapped := WrapSnetPath(src, dst, p)
		if !contains(entry.paths, wrapped.Fingerprint) {
			entry.paths = append(entry.paths, wrapped)
		}
	}

	entry.lastRefresh = time.Now()
	entry.lastError = nil
	pp.inflight[k] = false

	cb = pp.onRefresh
	shouldCallCallback = cb != nil
	pathCount = len(entry.paths)

	pp.mu.Unlock()

	log.Printf("[PATHPOOL] Refresh success: src=%s dst=%s paths=%d reason=%s", src, dst, pathCount, reason)

	if shouldCallCallback {
		cb(src, dst)
	}
}

// RefreshKnownPairs refreshes all IA pairs the PathPool has seen before.
// It is used by the periodic refresh loop to keep known path entries fresh.
func (pp *PathPool) RefreshKnownPairs(reason string) {
	pairs := pp.knownPairsSnapshot()

	if len(pairs) == 0 {
		log.Printf("[PATHPOOL] RefreshKnownPairs: no known pairs reason=%s", reason)
		return
	}

	log.Printf("[PATHPOOL] RefreshKnownPairs: pairs=%d reason=%s", len(pairs), reason)

	for _, pair := range pairs {
		pp.RefreshAsync(pair.Src, pair.Dst, reason)
	}
}

// knownPairsSnapshot returns a copy of all known IA pairs.
// The copy lets refresh logic iterate without holding the PathPool lock.
func (pp *PathPool) knownPairsSnapshot() []IAPair {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	pairs := make([]IAPair, 0, len(pp.known))

	for k := range pp.known {
		pairs = append(pairs, IAPair{
			Src: k.src,
			Dst: k.dst,
		})
	}

	return pairs
}

// refreshLoop periodically refreshes all known IA pairs.
// This keeps cached paths up to date even when no new packet triggers a miss.
func (pp *PathPool) refreshLoop() {
	ticker := time.NewTicker(pp.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pp.closed:
			return
		case <-ticker.C:
			pp.RefreshKnownPairs("timer")
		}
	}
}

// shouldRefreshSoon reports whether cached paths are close enough to expiry
// that the PathPool should refresh them in the background.
func shouldRefreshSoon(paths []CachedPath, before time.Duration) bool {
	if len(paths) == 0 {
		return true
	}

	now := time.Now()
	threshold := now.Add(before)

	for _, p := range paths {
		if p.Expiry.IsZero() {
			continue
		}

		if p.Expiry.Before(threshold) {
			return true
		}
	}

	return false
}
