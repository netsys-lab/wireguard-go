package pathpool

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

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
}

// PathPool caches snet.Path objects between ISD-AS pairs.
type PathPool struct {
	mu        sync.Mutex
	cache     map[key]*pathsEntry
	closed    chan struct{}
	retriever PathRetriever // logic to fetch paths if missing
}

// NewPathPool creates a new path pool.
// If retriever is provided, the pool will automatically fetch paths on cache miss.
func NewPathPool(retriever PathRetriever) *PathPool {
	pp := &PathPool{
		cache:     make(map[key]*pathsEntry),
		closed:    make(chan struct{}),
		retriever: retriever,
	}
	go pp.cleanupLoop()
	return pp
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

// Get retrieves valid paths for a given src/dst pair.
// If paths are missing or expired, it attempts to fetch them using the retriever.
func (pp *PathPool) Get(ctx context.Context, src, dst addr.IA) ([]CachedPath, error) {
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
		// Return a copy to ensure thread safety for the caller
		result := make([]CachedPath, len(valid))
		copy(result, valid)
		return result, nil
	}

	// 2. Cache Miss: Retrieve from network
	// We do this OUTSIDE the lock to avoid blocking other cache reads/writes
	if pp.retriever == nil {
		return nil, nil
	}

	// RetrievePaths implementation (SciondRetriever) should handle its own timeouts/context
	newPaths, err := pp.retriever.RetrievePaths(ctx, src, dst)
	if err != nil {
		return nil, err
	}

	if len(newPaths) == 0 {
		return nil, nil
	}

	// 3. Add new paths to cache (Add handles locking)
	pp.Add(src, dst, newPaths)

	// 4. Convert and return the new paths
	// We reconstruct the result here to avoid acquiring the lock again or calling Get recursively
	result := make([]CachedPath, 0, len(newPaths))
	for _, p := range newPaths {
		result = append(result, WrapSnetPath(src, dst, p))
	}

	return result, nil
}

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
func WrapSnetPath(src, dst addr.IA, p snet.Path) CachedPath {
	var expiry time.Time
	if meta := p.Metadata(); meta != nil {
		expiry = meta.Expiry
	}
	fp := snet.Fingerprint(p).String()

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
