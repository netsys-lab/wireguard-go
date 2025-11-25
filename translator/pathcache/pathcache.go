package pathcache

import (
	//"context"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	//"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

// FOR GOROUTINES AUTOMATIC REFRESH
/*
// The Fetcher is how the refresher asks my path provider for new Paths
//type Fetcher func(ctx context.Context, src, dst addr.IA) ([]snet.Path, error)


type RefreshOptions struct {
	Period         time.Duration // e.g. 30 * time.Second
	MaxConcurrency int           // e.g. 4
	// optional: small jitter to avoid thundering herd
	Jitter time.Duration // e.g. 250 * time.Millisecond
}












*/

// This is the key struct, addr.IA in SCION is a uint64 under the hood → comparable.
// A Go struct of comparable fields is itself comparable, so it can be used as a map key
// You don’t need to define a hasher; Go’s map handles hashing/equality automatically
type Route struct {
	Src addr.IA
	Dst addr.IA
}

// Cache stores snet.Path objects per (Src,Dst).
type Cache struct {
	mu    sync.RWMutex
	store map[Route][]snetpath.Path
}

// New creates an empty cache.
func New() *Cache {
	return &Cache{store: make(map[Route][]snetpath.Path)}
}

// Get retrieves a value by key.
// The bool tells you if the key existed.
func (c *Cache) Lookup(src, dst addr.IA) ([]snetpath.Path, bool) {
	key := Route{Src: src, Dst: dst}
	c.mu.RLock()
	defer c.mu.RUnlock()
	paths, ok := c.store[key]
	if !ok || len(paths) == 0 {
		return nil, false
	}
	out := append([]snetpath.Path(nil), paths...)
	return out, true
}

func (c *Cache) StorePaths(src, dst addr.IA, paths []snetpath.Path) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := Route{Src: src, Dst: dst}
	// defensive deep copy
	c.store[key] = append([]snetpath.Path(nil), paths...)
	c.mu.Unlock()
}

// Set stores a value by key.
func (c *Cache) Store(src, dst addr.IA, path snetpath.Path) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := Route{Src: src, Dst: dst}
	// defensive deep copy
	c.store[key] = append(c.store[key], path)
	c.mu.Unlock()
}

// DeleteRoute removes all paths for (src,dst).
func (c *Cache) DeleteRoute(src, dst addr.IA) {
	key := Route{Src: src, Dst: dst}
	c.mu.Lock()
	delete(c.store, key)
	c.mu.Unlock()
}

func (c *Cache) Refresh(src, dst addr.IA, newPaths []snetpath.Path) {
	key := Route{Src: src, Dst: dst}
	c.mu.Lock()
	c.store[key] = append([]snetpath.Path(nil), newPaths...) // replace
	c.mu.Unlock()
}
