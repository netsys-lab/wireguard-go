package pathcache

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
	//go pp.cleanupLoop()
	return pp
}

// Dummy for now
func (pp *PathPool) Get(ctx context.Context, src, dst addr.IA) ([]CachedPath, error) {
	return nil, nil
}
