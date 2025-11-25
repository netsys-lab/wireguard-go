package pathcache

import (
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

// key identifies a path pool entry (by source/destination IA pair)
type key struct {
	src, dst addr.IA
}

// pathsEntry represents cached paths and metadata
type pathsEntry struct {
	paths       []snet.Path
	lastRefresh time.Time
}

// PathPool is a minimal standalone reimplementation of PAN’s path pool.
// It caches snet.Path objects and refetches them on demand.
type PathPool struct {
	mu     sync.Mutex
	cache  map[key]*pathsEntry
	closed chan struct{}
}

// NewPathPool creates a new empty path pool
func NewPathPool() *PathPool {
	pp := &PathPool{
		cache:  make(map[key]*pathsEntry),
		closed: make(chan struct{}),
	}
	go pp.cleanupLoop()
	return pp
}

// Add adds new paths for a given src/dst IA pair
func (pp *PathPool) Add(src, dst addr.IA, paths []snet.Path) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	k := key{src: src, dst: dst}
	entry, ok := pp.cache[k]
	if !ok {
		entry = &pathsEntry{}
		pp.cache[k] = entry
	}
	// deduplicate
	for _, p := range paths {
		if !contains(entry.paths, p) {
			entry.paths = append(entry.paths, p)
		}
	}
	entry.lastRefresh = time.Now()
}

// Get retrieves valid paths for a given src/dst pair.
// If none exist, it triggers a placeholder fetch.
func (pp *PathPool) Get(ctx context.Context, src, dst addr.IA) ([]snet.Path, error) {
	pp.mu.Lock()
	entry, ok := pp.cache[key{src, dst}]
	pp.mu.Unlock()

	if ok && len(entry.paths) > 0 {
		// filter out expired
		valid := filterValid(entry.paths)
		if len(valid) > 0 {
			return valid, nil
		}
	}

	// Placeholder: fetch paths (stub)
	fetched := pp.fetchPlaceholderPaths(src, dst)
	if len(fetched) > 0 {
		pp.Add(src, dst, fetched)
		return fetched, nil
	}

	return nil, nil
}

// fetchPlaceholderPaths simulates a path lookup from SCIOND or pathmgr.
func (pp *PathPool) fetchPlaceholderPaths(src, dst addr.IA) []snet.Path {
	// This is where you’d integrate with the real resolver later.
	// For now, return a dummy path slice.
	return []snet.Path{}
}

// Cleanup removes expired or old paths manually
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

// contains checks if a path is already stored
func contains(paths []snet.Path, p snet.Path) bool {
	/*
		//TODO: Add Fingerprint???
			for _, existing := range paths {


					if existing.Fingerprint() == p.Fingerprint() {
						return true
					}

			}
	*/
	return false
}

// filterValid returns only unexpired paths
func filterValid(paths []snet.Path) []snet.Path {
	valid := []snet.Path{}
	/*
		//TODO: Add .Expiry???
			now := time.Now()
			for _, p := range paths {


					if p.Expiry().After(now) {
						valid = append(valid, p)
					}

			}
	*/
	return valid
}
