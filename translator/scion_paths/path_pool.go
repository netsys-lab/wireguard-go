package scion_paths

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

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
func (pp *PathPool) Get(ctx context.Context, src, dst addr.IA) ([]CachedPath, error) {
	pp.mu.Lock()
	entry, ok := pp.cache[key{src, dst}]
	pp.mu.Unlock()

	if ok && len(entry.paths) > 0 {
		valid := filterValid(entry.paths)
		if len(valid) > 0 {
			return valid, nil
		}
	}

	// No valid paths cached
	return nil, nil
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

	return CachedPath{
		Src:         src,
		Dst:         dst,
		Path:        p,
		NextHop:     p.UnderlayNextHop(),
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
