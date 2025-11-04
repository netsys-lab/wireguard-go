package pathcache

import (
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	//"github.com/scionproto/scion/pkg/snet"
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
	store map[Route][][]byte
}

// New creates an empty cache.
func New() *Cache {
	return &Cache{
		store: make(map[Route][][]byte),
	}
}

// Get retrieves a value by key.
// The bool tells you if the key existed.
func (c *Cache) Lookup(src, dst addr.IA) ([]byte, bool) {
	key := Route{Src: src, Dst: dst}
	c.mu.RLock()
	defer c.mu.RUnlock() // what is this defer for?
	paths, ok := c.store[key]
	if !ok || len(paths) == 0 {
		return nil, false
	}
	//Return a Copy
	out := make([]byte, len(paths[0]))
	copy(out, paths[0])
	return out, true
}

// Set stores a value by key.
func (c *Cache) Store(src, dst addr.IA, pathBytesList [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := Route{Src: src, Dst: dst}
	// defensive deep copy
	cp := make([][]byte, len(pathBytesList))
	for i := range pathBytesList {
		if pathBytesList[i] == nil {
			continue
		}
		b := make([]byte, len(pathBytesList[i]))
		copy(b, pathBytesList[i])
		cp[i] = b
	}
	c.store[key] = cp
}
