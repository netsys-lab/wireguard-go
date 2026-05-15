package pathpool

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

var ErrPathPending = errors.New("path refresh pending")

const (
	pathQueryTimeout   = 10 * time.Second
	minRefreshInterval = 5 * time.Second
)

type RefreshCallback func(src, dst addr.IA)

// PathRetriever defines the interface for fetching paths from a daemon/network.
// SciondRetriever implements this.
type PathRetriever interface {
	RetrievePaths(ctx context.Context, src, dst addr.IA) ([]snet.Path, error)
}

// key identifies a path pool entry (by source/destination IA pair)
type key struct {
	src, dst addr.IA
}

// CachedPath is a lightweight wrapper around snet.Path with metadata.
type CachedPath struct {
	Src         addr.IA
	Dst         addr.IA
	Path        snet.Path
	NextHop     *net.UDPAddr
	Fingerprint string
	Expiry      time.Time
}

// pathsEntry represents cached paths and metadata
type pathsEntry struct {
	paths       []CachedPath
	lastRefresh time.Time
	lastError   error
}

// PathPool caches snet.Path objects between ISD-AS pairs.
type PathPool struct {
	mu        sync.Mutex
	cache     map[key]*pathsEntry
	inflight  map[key]bool
	closed    chan struct{}
	retriever PathRetriever

	onRefresh RefreshCallback
}

// NewPathPool creates a new path pool.
// If retriever is provided, the pool will automatically fetch paths on cache miss.
func NewPathPool(retriever PathRetriever) *PathPool {
	pp := &PathPool{
		cache:     make(map[key]*pathsEntry),
		inflight:  make(map[key]bool),
		closed:    make(chan struct{}),
		retriever: retriever,
	}
	go pp.cleanupLoop()
	return pp
}

// Calllback setter
func (pp *PathPool) SetRefreshCallback(cb RefreshCallback) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	pp.onRefresh = cb
	log.Printf("[PATHPOOL] refresh callback registered")
}

// Cache only lookup:
func (pp *PathPool) GetCached(src, dst addr.IA) []CachedPath {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	k := key{src: src, dst: dst}
	entry, ok := pp.cache[k]
	if !ok || len(entry.paths) == 0 {
		log.Printf("[PATHPOOL] cache lookup miss: src=%s dst=%s no-entry", src, dst)
		return nil
	}

	valid := filterValid(entry.paths)
	entry.paths = valid

	if len(valid) == 0 {
		log.Printf("[PATHPOOL] cache lookup miss: src=%s dst=%s expired", src, dst)
		return nil
	}

	result := make([]CachedPath, len(valid))
	copy(result, valid)

	log.Printf("[PATHPOOL] cache lookup hit: src=%s dst=%s valid=%d", src, dst, len(result))
	return result
}

// Replace Paths
func (pp *PathPool) Replace(src, dst addr.IA, paths []snet.Path) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	k := key{src: src, dst: dst}
	entry := &pathsEntry{
		paths:       make([]CachedPath, 0, len(paths)),
		lastRefresh: time.Now(),
		lastError:   nil,
	}

	for _, p := range paths {
		wrapped := WrapSnetPath(src, dst, p)
		if !contains(entry.paths, wrapped.Fingerprint) {
			entry.paths = append(entry.paths, wrapped)
		}
	}

	pp.cache[k] = entry

	log.Printf("[PATHPOOL] cache replaced: src=%s dst=%s paths=%d", src, dst, len(entry.paths))
}

// Async Refresh:
func (pp *PathPool) RefreshAsync(src, dst addr.IA, reason string) {
	k := key{src: src, dst: dst}

	pp.mu.Lock()

	if pp.retriever == nil {
		pp.mu.Unlock()
		log.Printf("[PATHPOOL] refresh skipped: no retriever src=%s dst=%s reason=%s", src, dst, reason)
		return
	}

	if entry := pp.cache[k]; entry != nil {
		if time.Since(entry.lastRefresh) < minRefreshInterval {
			pp.mu.Unlock()
			log.Printf("[PATHPOOL] refresh skipped: recently refreshed src=%s dst=%s reason=%s lastRefresh=%s",
				src, dst, reason, entry.lastRefresh.Format(time.RFC3339Nano))
			return
		}
	}

	if pp.inflight[k] {
		pp.mu.Unlock()
		log.Printf("[PATHPOOL] refresh skipped: already in-flight src=%s dst=%s reason=%s", src, dst, reason)
		return
	}

	pp.inflight[k] = true
	pp.mu.Unlock()

	log.Printf("[PATHPOOL] refresh started: src=%s dst=%s reason=%s", src, dst, reason)

	go func() {
		start := time.Now()

		defer func() {
			pp.mu.Lock()
			delete(pp.inflight, k)
			pp.mu.Unlock()

			log.Printf("[PATHPOOL] refresh ended: src=%s dst=%s reason=%s duration=%s",
				src, dst, reason, time.Since(start))
		}()

		ctx, cancel := context.WithTimeout(context.Background(), pathQueryTimeout)
		defer cancel()

		newPaths, err := pp.retriever.RetrievePaths(ctx, src, dst)
		if err != nil {
			log.Printf("[PATHPOOL] refresh failed: src=%s dst=%s reason=%s err=%v", src, dst, reason, err)

			pp.mu.Lock()
			entry := pp.cache[k]
			if entry == nil {
				entry = &pathsEntry{}
				pp.cache[k] = entry
			}
			entry.lastError = err
			entry.lastRefresh = time.Now()
			pp.mu.Unlock()
			return
		}

		if len(newPaths) == 0 {
			log.Printf("[PATHPOOL] refresh returned 0 paths: src=%s dst=%s reason=%s", src, dst, reason)

			pp.mu.Lock()
			entry := pp.cache[k]
			if entry == nil {
				entry = &pathsEntry{}
				pp.cache[k] = entry
			}
			entry.lastError = nil
			entry.lastRefresh = time.Now()
			pp.mu.Unlock()
			return
		}

		pp.Replace(src, dst, newPaths)

		pp.mu.Lock()
		cb := pp.onRefresh
		pp.mu.Unlock()

		if cb != nil {
			log.Printf("[PATHPOOL] invoking refresh callback: src=%s dst=%s reason=%s", src, dst, reason)
			go cb(src, dst)
		} else {
			log.Printf("[PATHPOOL] no refresh callback registered: src=%s dst=%s reason=%s", src, dst, reason)
		}
	}()
}

// Add manually adds paths to the pool
func (pp *PathPool) Add(src, dst addr.IA, paths []snet.Path) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	k := key{src: src, dst: dst}
	entry, ok := pp.cache[k]
	if !ok {
		entry = &pathsEntry{}
		pp.cache[k] = entry
	}
	for _, p := range paths {
		wrapped := WrapSnetPath(src, dst, p)
		if !contains(entry.paths, wrapped.Fingerprint) {
			entry.paths = append(entry.paths, wrapped)
		}
	}
	entry.lastRefresh = time.Now()
}

// Get Paths
func (pp *PathPool) Get(ctx context.Context, src, dst addr.IA) ([]CachedPath, error) {
	log.Printf("[PATHPOOL] Get: src=%s dst=%s", src, dst)

	valid := pp.GetCached(src, dst)
	if len(valid) > 0 {
		return valid, nil
	}

	log.Printf("[PATHPOOL] cache miss: scheduling async refresh src=%s dst=%s", src, dst)
	pp.RefreshAsync(src, dst, "cache-miss")

	return nil, ErrPathPending
}

// Get retrieves valid paths for a given src/dst pair.
// If paths are missing or expired, it attempts to fetch them using the retriever.
/* func (pp *PathPool) Get(ctx context.Context, src, dst addr.IA) ([]CachedPath, error) {
	log.Printf("[PATHPOOL] Get: src=%s, dst=%s", src, dst)

	// 1. Try to get from cache
	pp.mu.Lock()
	entry, ok := pp.cache[key{src, dst}]

	var valid []CachedPath
	if ok && len(entry.paths) > 0 {
		// Perform lazy cleanup and check if we have valid paths
		valid = filterValid(entry.paths)
		entry.paths = valid // update cache with filtered list
	}
	pp.mu.Unlock()

	// If we found valid paths, return them immediately
	if len(valid) > 0 {
		log.Printf("[PATHPOOL] Cache hit: returning %d valid paths", len(valid))
		// Return a copy to ensure thread safety for the caller
		result := make([]CachedPath, len(valid))
		copy(result, valid)
		return result, nil
	}

	log.Printf("[PATHPOOL] Cache miss - trying retriever")

	// 2. Cache Miss: Retrieve from network
	// We do this OUTSIDE the lock to avoid blocking other cache reads/writes
	if pp.retriever == nil {
		log.Printf("[PATHPOOL] WARNING: retriever is NIL - cannot fetch paths")
		return nil, nil
	}

	// RetrievePaths implementation (SciondRetriever) should handle its own timeouts/context
	newPaths, err := pp.retriever.RetrievePaths(ctx, src, dst)
	if err != nil {
		log.Printf("[PATHPOOL] ERROR: retriever.RetrievePaths failed: %v", err)
		return nil, err
	}

	if len(newPaths) == 0 {
		log.Printf("[PATHPOOL] WARNING: retriever returned 0 paths")
		return nil, nil
	}

	log.Printf("[PATHPOOL] Retrieved %d new paths from network", len(newPaths))

	// 3. Add new paths to cache (Add handles locking)
	pp.Add(src, dst, newPaths)

	// 4. Convert and return the new paths
	// We reconstruct the result here to avoid acquiring the lock again or calling Get recursively
	result := make([]CachedPath, 0, len(newPaths))
	for _, p := range newPaths {
		result = append(result, WrapSnetPath(src, dst, p))
	}

	return result, nil
} */

// Cleanup removes expired or old paths
func (pp *PathPool) Cleanup() {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	for k, entry := range pp.cache {
		entry.paths = filterValid(entry.paths)
		if len(entry.paths) == 0 {
			delete(pp.cache, k)
		}
	}
}

// cleanupLoop runs periodically to remove expired paths
func (pp *PathPool) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-pp.closed:
			return
		case <-ticker.C:
			pp.Cleanup()
		}
	}
}

// Close stops the background cleanup loop
func (pp *PathPool) Close() {
	close(pp.closed)
}

// WrapSnetPath converts snet.Path into a CachedPath wrapper.
// Fingerprint needs snet.PathInterface instead of snet.Path
// SCION APIs, the PathInterfaces are exposed via Metadata()
func WrapSnetPath(src, dst addr.IA, p snet.Path) CachedPath {
	var expiry time.Time
	if meta := p.Metadata(); meta != nil {
		expiry = meta.Expiry
	}

	fp := snet.Fingerprint(p.Metadata().Interfaces).String()

	// Safety check for UnderlayNextHop
	var nextHop *net.UDPAddr
	if nh := p.UnderlayNextHop(); nh != nil {
		nextHop = &net.UDPAddr{
			IP:   nh.IP,
			Port: nh.Port,
			Zone: nh.Zone,
		}
	}

	return CachedPath{
		Src:         src,
		Dst:         dst,
		Path:        p,
		NextHop:     nextHop,
		Fingerprint: fp,
		Expiry:      expiry,
	}
}

// contains checks if a path fingerprint is already stored
func contains(paths []CachedPath, fp string) bool {
	for _, existing := range paths {
		if existing.Fingerprint == fp {
			return true
		}
	}
	return false
}

// filterValid returns only unexpired paths
func filterValid(paths []CachedPath) []CachedPath {
	valid := []CachedPath{}
	now := time.Now()
	for _, p := range paths {
		if p.Expiry.IsZero() || p.Expiry.After(now) {
			valid = append(valid, p)
		}
	}
	return valid
}
