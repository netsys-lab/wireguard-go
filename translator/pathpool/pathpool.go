package pathpool

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

// contextKeyRefreshID is the context key for carrying refreshId through the
// path resolution pipeline so that sub-phases (LocalIA, Interfaces, Paths)
// can log correlated events.
type contextKeyRefreshID struct{}

// ContextWithRefreshID returns a context carrying the given refresh ID.
func ContextWithRefreshID(ctx context.Context, id uint64) context.Context {
	return context.WithValue(ctx, contextKeyRefreshID{}, id)
}

// RefreshIDFromContext extracts the refresh ID from a context.
// Returns 0, false if no refresh ID is present.
func RefreshIDFromContext(ctx context.Context) (uint64, bool) {
	id, ok := ctx.Value(contextKeyRefreshID{}).(uint64)
	return id, ok
}

var (
	// ErrPathPending means no valid cached path is currently available,
	// but an async refresh has been scheduled.
	ErrPathPending = errors.New("path refresh pending")

	// ErrNoPaths means the retriever completed successfully but returned no paths.
	ErrNoPaths = errors.New("path refresh returned no paths")
)

const (
	defaultRefreshInterval     = 2 * time.Minute
	defaultRefreshBeforeExpiry = 30 * time.Second
	defaultQueryTimeout        = 30 * time.Second
)

// PathRetriever defines the interface for fetching paths from a daemon/network.
// SciondRetriever implements this.
type PathRetriever interface {
	RetrievePaths(ctx context.Context, src, dst addr.IA) ([]snet.Path, error)
}

// IAPair identifies a source/destination IA pair.
// Startup prefetch and periodic refresh operate on these pairs.
type IAPair struct {
	Src addr.IA
	Dst addr.IA
}

// RefreshCallback is called after a successful async path refresh.
// The Device uses this to flush queued packets for the refreshed IA pair.
type RefreshCallback func(src, dst addr.IA)

// RefreshStatus reports the state of an async path refresh.
type RefreshStatus struct {
	ID      uint64 // monotonic refresh ID assigned to this refresh
	Started bool   // true if a new refresh was started; false if already inflight
}

// inflightRefresh tracks an in-progress path refresh for one IA pair.
type inflightRefresh struct {
	id        uint64
	startedAt time.Time
}

// key identifies a path pool entry by source/destination IA pair.
type key struct {
	src addr.IA
	dst addr.IA
}

// CachedPath is a lightweight wrapper around snet.Path with metadata.
// This is what the translator uses after fetching paths from the pool.
type CachedPath struct {
	Src         addr.IA
	Dst         addr.IA
	Path        snet.Path
	NextHop     *net.UDPAddr
	Fingerprint string
	Expiry      time.Time
}

// pathsEntry represents cached paths and metadata for one IA pair.
type pathsEntry struct {
	paths       []CachedPath
	lastRefresh time.Time
	lastError   error
}

// PathPool caches SCION paths between IA pairs.
// It returns cached paths immediately and refreshes paths asynchronously.
type PathPool struct {
	mu       sync.Mutex
	cache    map[key]*pathsEntry
	inflight map[key]*inflightRefresh
	known    map[key]struct{}

	closed    chan struct{}
	retriever PathRetriever

	onRefresh RefreshCallback

	refreshIDCounter uint64
	refreshInterval  time.Duration
	refreshBeforeExpiry time.Duration
	queryTimeout        time.Duration
}

// NewPathPool creates a PathPool and starts its background maintenance loops.
// The pool stores cached SCION paths by src/dst IA pair and can refresh paths
// asynchronously through the configured PathRetriever.
func NewPathPool(retriever PathRetriever) *PathPool {
	pp := &PathPool{
		cache:               make(map[key]*pathsEntry),
		inflight:            make(map[key]*inflightRefresh),
		known:               make(map[key]struct{}),
		closed:              make(chan struct{}),
		retriever:           retriever,
		refreshInterval:     defaultRefreshInterval,
		refreshBeforeExpiry: defaultRefreshBeforeExpiry,
		queryTimeout:        defaultQueryTimeout,
	}

	go pp.cleanupLoop()
	go pp.refreshLoop()

	return pp
}

// Add manually appends paths to the cache without replacing existing entries.
// This is useful for tests or manual insertion. Normal refresh logic replaces
// old paths instead of appending.
func (pp *PathPool) Add(src, dst addr.IA, paths []snet.Path) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	k := key{src: src, dst: dst}
	pp.known[k] = struct{}{}

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
	entry.lastError = nil

	log.Printf("[PATHPOOL] Add: src=%s dst=%s added=%d total=%d", src, dst, len(paths), len(entry.paths))
}

// GetCached performs a cache-only lookup for valid paths.
// It never fetches paths from the network. Expired paths are removed lazily,
// and a copy of the valid cached paths is returned to the caller.
func (pp *PathPool) GetCached(src, dst addr.IA) []CachedPath {
	k := key{src: src, dst: dst}

	pp.mu.Lock()
	defer pp.mu.Unlock()

	pp.known[k] = struct{}{}

	entry, ok := pp.cache[k]
	if !ok || len(entry.paths) == 0 {
		return nil
	}

	valid := filterValid(entry.paths)
	entry.paths = valid

	if len(valid) == 0 {
		return nil
	}

	result := make([]CachedPath, len(valid))
	copy(result, valid)
	return result
}

// Get retrieves currently valid cached paths for a src/dst IA pair.
// If no valid path is cached, it schedules an async refresh and returns
// ErrPathPending instead of blocking on network path retrieval.
//
// If valid paths exist but are close to expiry, the valid paths are returned
// immediately and a background refresh is scheduled.
func (pp *PathPool) Get(ctx context.Context, src, dst addr.IA) ([]CachedPath, error) {
	_ = ctx

	k := key{src: src, dst: dst}

	log.Printf("[SCION-PATH] event=cache-lookup src=%s dst=%s", src, dst)

	lookupStart := time.Now()

	pp.mu.Lock()

	pp.known[k] = struct{}{}

	entry, ok := pp.cache[k]

	var valid []CachedPath
	var refreshSoon bool

	if ok && len(entry.paths) > 0 {
		valid = filterValid(entry.paths)
		entry.paths = valid

		if len(valid) > 0 {
			refreshSoon = shouldRefreshSoon(valid, pp.refreshBeforeExpiry)
		}
	}

	pp.mu.Unlock()

	lookupDur := time.Since(lookupStart)

	if len(valid) > 0 {
		log.Printf("[SCION-PATH] event=cache-hit src=%s dst=%s valid=%d refreshSoon=%v elapsedMs=%d",
			src, dst, len(valid), refreshSoon, lookupDur.Milliseconds())

		if refreshSoon {
			pp.RefreshAsync(src, dst, "expiry-soon")
		}

		result := make([]CachedPath, len(valid))
		copy(result, valid)
		return result, nil
	}

	log.Printf("[SCION-PATH] event=cache-miss src=%s dst=%s elapsedMs=%d",
		src, dst, lookupDur.Milliseconds())

	pp.RefreshAsync(src, dst, "cache-miss")

	return nil, ErrPathPending
}

// Cleanup removes expired paths from all cache entries.
// Empty cache entries are deleted to keep the PathPool small.
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

// cleanupLoop periodically runs Cleanup until the PathPool is closed.
// It only removes expired paths; it does not fetch new paths.
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

// Close stops the PathPool background loops.
// All goroutines watching pp.closed should exit after this is called.
func (pp *PathPool) Close() {
	close(pp.closed)
}

// WrapSnetPath converts an snet.Path into a CachedPath.
// It extracts metadata needed by the cache and UI, such as expiry,
// fingerprint, and underlay next hop.
func WrapSnetPath(src, dst addr.IA, p snet.Path) CachedPath {
	var expiry time.Time
	var fingerprint string

	meta := p.Metadata()
	if meta != nil {
		expiry = meta.Expiry
		fingerprint = snet.Fingerprint(meta.Interfaces).String()
	} else {
		fingerprint = fmt.Sprintf("%s-%s-no-metadata", src, dst)
	}

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
		Fingerprint: fingerprint,
		Expiry:      expiry,
	}
}

// contains reports whether a path with the same fingerprint already exists.
// It is used to avoid storing duplicate paths for the same IA pair.
func contains(paths []CachedPath, fp string) bool {
	for _, existing := range paths {
		if existing.Fingerprint == fp {
			return true
		}
	}
	return false
}

// filterValid returns only paths that are not expired.
// Paths without an expiry are treated as valid.
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
