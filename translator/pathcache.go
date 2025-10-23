"""
This file contains the pathcache for the scion packet paths

https://github.com/lschulz/scion-cpp/blob/main/include/scion/path/cache.hpp
"""

package pathcache

import (
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

// Fetcher is your hook to obtain paths (e.g., via the SCION daemon).
// Implement this with daemon.Querier or any path source you prefer.
//type Fetcher func(ctx context.Context, srcIA, dstIA addr.IA) ([]snet.Path, error)

type key struct {
	src addr.IA
	dst addr.IA
}

type entry struct {
	paths  []snet.Path
	expiry time.Time
}

// Cache is a very small TTL cache for SCION paths keyed by (srcIA,dstIA).
type Cache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	fetcher Fetcher
	items   map[key]entry
}


// New creates a new path cache with the given TTL and fetcher.
func PathCache(ttl time.Duration, fetcher Fetcher) *Cache {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &Cache{
		ttl:     ttl,
		fetcher: fetcher,
		items:   make(map[key]entry),
	}
}

// Get returns cached paths for (srcIA,dstIA). If absent or expired,
// it calls the Fetcher, stores the result, and returns it.
func (c *Cache) Get(ctx context.Context, srcIA, dstIA addr.IA) ([]snet.Path, error) {
	k := key{src: srcIA, dst: dstIA}

	// Fast path: try read lock first.
	c.mu.RLock()
	if e, ok := c.items[k]; ok && time.Now().Before(e.expiry) {
		paths := e.paths
		c.mu.RUnlock()
		return paths, nil
	}
	c.mu.RUnlock()


	"""
	Ab hier checke ich noch nicht
	"""

	// Miss or expired: fetch under write lock (double-checking).
	c.mu.Lock()
	defer c.mu.Unlock()

	// Another goroutine might have populated it meanwhile.
	if e, ok := c.items[k]; ok && time.Now().Before(e.expiry) {
		return e.paths, nil
	}

	paths, err := c.fetcher(ctx, srcIA, dstIA)
	if err != nil {
		// On error, keep (and return) stale value if present.
		if e, ok := c.items[k]; ok && len(e.paths) > 0 {
			return e.paths, nil
		}
		return nil, err
	}
	c.items[k] = entry{
		paths:  paths,
		expiry: time.Now().Add(c.ttl),
	}
	return paths, nil
}


"""


func main() {
	src := addr.MustIAFrom(1, 0x110) // e.g., "1-ff00:0:110"
	dst := addr.MustIAFrom(1, 0x111) // e.g., "1-ff00:0:111"

	cache := pathcache.New(10*time.Second, example.DaemonFetcher(""))

	ctx := context.Background()
	paths, err := cache.Get(ctx, src, dst)
	if err != nil {
		panic(err)
	}
	for i, p := range paths {
		// p is snet.Path; print something simple about it
		fmt.Printf("[%d] %s\n", i, snet.PathDesc(p))
	}
}

"""