package pathcache

import (
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

// This is the key struct, addr.IA in SCION is a uint64 under the hood → comparable.
// A Go struct of comparable fields is itself comparable, so it can be used as a map key
// You don’t need to define a hasher; Go’s map handles hashing/equality automatically
type Route struct {
	Src addr.IA
	Dst addr.IA
}

// Cache is a small, thread-safe map.
type Cache struct {
	mu    sync.RWMutex
	store map[Route][]snet.Path
}

// New creates an empty cache.
func New() *Cache {
	return &Cache{
		store: make(map[Route][]snet.Path),
	}
}

// Get retrieves a value by key.
// The bool tells you if the key existed.
func (c *Cache) Lookup(src, dst snet.UDPAddr) ([]snet.Path, bool) {
	key := Route{Src: src.IA, Dst: dst.IA}
	c.mu.RLock()
	paths, ok := c.store[key]
	c.mu.RUnlock()
	return paths, ok
}

// Set stores a value by key.
func (c *Cache) Store(src, dst snet.UDPAddr, paths []snet.Path) {
	key := Route{Src: src.IA, Dst: dst.IA}
	c.mu.Lock()
	c.store[key] = paths
	c.mu.Unlock()
}
