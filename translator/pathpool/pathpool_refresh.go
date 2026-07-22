package pathpool

import (
	"context"
	"errors"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"golang.zx2c4.com/wireguard/scionlog"
)

// SetRefreshCallback registers a callback that is called after a successful
// async path refresh. The Device uses this to flush pending packets once fresh
// paths are available.
func (pp *PathPool) SetRefreshCallback(cb RefreshCallback) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	pp.onRefresh = cb
	pp.log.Infof(scionlog.ComponentPath, "[PATHPOOL] refresh callback registered")
}

// PrefetchAsync starts async refreshes for configured IA pairs during startup.
// It is used to warm the path cache before the first packet for a known
// destination arrives.
func (pp *PathPool) PrefetchAsync(pairs []IAPair) {
	if len(pairs) == 0 {
	pp.log.Infof(scionlog.ComponentPath, "[PATHPOOL] PrefetchAsync: no pairs configured")
		return
	}

	pp.log.Infof(scionlog.ComponentPath, "[PATHPOOL] PrefetchAsync: pairs=%d", len(pairs))

	for _, pair := range pairs {
		pp.RefreshAsync(pair.Src, pair.Dst, "startup-prefetch")
	}
}

// RefreshAsync schedules a non-blocking path refresh for a src/dst IA pair.
// It remembers the IA pair, prevents duplicate in-flight refreshes, and starts
// a background worker if no refresh is currently running.
// Returns RefreshStatus indicating whether a new refresh was started and its ID.
func (pp *PathPool) RefreshAsync(src, dst addr.IA, reason string) RefreshStatus {
	k := key{src: src, dst: dst}

	pp.mu.Lock()

	pp.known[k] = struct{}{}

	if pp.retriever == nil {
	pp.log.Infof(scionlog.ComponentPath, "[PATHPOOL] RefreshAsync skipped: retriever nil src=%s dst=%s reason=%s", src, dst, reason)
		pp.mu.Unlock()
		return RefreshStatus{}
	}

	if inflight, ok := pp.inflight[k]; ok {
	pp.log.Infof(scionlog.ComponentPath, "[PATHPOOL] RefreshAsync skipped: already inflight id=%d src=%s dst=%s reason=%s", inflight.id, src, dst, reason)
		pp.mu.Unlock()
		return RefreshStatus{ID: inflight.id, Started: false}
	}

	pp.refreshIDCounter++
	id := pp.refreshIDCounter
	pp.inflight[k] = &inflightRefresh{
		id:        id,
		startedAt: time.Now(),
	}
	pp.mu.Unlock()

	pp.log.Infof(scionlog.ComponentPath, "[SCION-PATH] refreshId=%d event=refresh-async src=%s dst=%s reason=%s started=%v", id, src, dst, reason, true)

	go pp.refreshWorker(src, dst, reason, id)

	return RefreshStatus{ID: id, Started: true}
}

// refreshWorker performs the actual path fetch in the background.
// It calls the retriever, updates the cache or lastError state, clears the
// in-flight entry, and calls the refresh callback after a successful update.
// The inflight entry is deleted on every exit path (success, error, no paths).
func (pp *PathPool) refreshWorker(src, dst addr.IA, reason string, refreshID uint64) {
	k := key{src: src, dst: dst}
	refreshStart := time.Now()

	pp.log.Infof(scionlog.ComponentPath, "[SCION-PATH] refreshId=%d event=refresh-started src=%s dst=%s reason=%s", refreshID, src, dst, reason)

	ctx, cancel := context.WithTimeout(context.Background(), pp.queryTimeout)
	defer cancel()

	// Pass refreshId through context so sub-phases can log correlated events.
	ctx = ContextWithRefreshID(ctx, refreshID)

	// Deferred cleanup: always remove the inflight entry when done.
	defer func() {
		pp.mu.Lock()
		delete(pp.inflight, k)
		pp.mu.Unlock()
	}()

	paths, err := pp.retriever.RetrievePaths(ctx, src, dst)
	retrieveElapsed := time.Since(refreshStart)

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
		pp.mu.Unlock()

		// Categorize the error for diagnostics
		errorCategory := "connector-error"
		cause := err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			errorCategory = "context-deadline"
		}

		// Compute remaining deadline
		remainingMs := 0
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining > 0 {
				remainingMs = int(remaining.Milliseconds())
			}
		}

		pp.log.Infof(scionlog.ComponentPath, "[SCION-PATH] refreshId=%d event=refresh-failed src=%s dst=%s elapsedMs=%d remainingDeadlineMs=%d errorCategory=%s cause=%q reason=%s",
			refreshID, src, dst, retrieveElapsed.Milliseconds(), remainingMs, errorCategory, cause, reason)
		return
	}

	if len(paths) == 0 {
		entry.lastError = ErrNoPaths
		pp.mu.Unlock()

		pp.log.Infof(scionlog.ComponentPath, "[SCION-PATH] refreshId=%d event=refresh-failed src=%s dst=%s elapsedMs=%d errorCategory=no-paths reason=%s",
			refreshID, src, dst, retrieveElapsed.Milliseconds(), reason)
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

	cb = pp.onRefresh
	shouldCallCallback = cb != nil
	pathCount = len(entry.paths)

	pp.mu.Unlock()

	pp.log.Infof(scionlog.ComponentPath, "[SCION-PATH] refreshId=%d event=refresh-success src=%s dst=%s paths=%d elapsedMs=%d reason=%s",
		refreshID, src, dst, pathCount, retrieveElapsed.Milliseconds(), reason)

	if shouldCallCallback {
		cb(src, dst)
	}
}

// RefreshKnownPairs refreshes all IA pairs the PathPool has seen before.
// It is used by the periodic refresh loop to keep known path entries fresh.
func (pp *PathPool) RefreshKnownPairs(reason string) {
	pairs := pp.knownPairsSnapshot()

	if len(pairs) == 0 {
	pp.log.Infof(scionlog.ComponentPath, "[PATHPOOL] RefreshKnownPairs: no known pairs reason=%s", reason)
		return
	}

	pp.log.Infof(scionlog.ComponentPath, "[PATHPOOL] RefreshKnownPairs: pairs=%d reason=%s", len(pairs), reason)

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
