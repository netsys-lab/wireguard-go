package pathpolicy

import (
	"math/rand"
	"sort"
	"time"

	pathpool "golang.zx2c4.com/wireguard/translator/pathpool"
)

// SortPaths sorts the given paths according to the specified orderings.
// Orderings are applied left-to-right with a stable sort, so the effect of
// earlier orderings may remain visible in case of ties.
func SortPaths(orderings []string, paths []pathpool.CachedPath) []pathpool.CachedPath {
	if len(orderings) == 0 || len(paths) <= 1 {
		return paths
	}

	// Apply orderings in reverse so the first ordering has the highest priority
	// (stable sort preserves earlier ordering for ties).
	for i := len(orderings) - 1; i >= 0; i-- {
		applyOrdering(orderings[i], paths)
	}

	return paths
}

// applyOrdering applies a single ordering to the path slice.
func applyOrdering(ordering string, paths []pathpool.CachedPath) {
	switch ordering {
	case "random":
		shufflePaths(paths)

	case "hops_asc":
		sort.SliceStable(paths, func(i, j int) bool {
			return hopCount(paths[i]) < hopCount(paths[j])
		})

	case "hops_desc":
		sort.SliceStable(paths, func(i, j int) bool {
			return hopCount(paths[i]) > hopCount(paths[j])
		})

	case "meta_latency_asc":
		sort.SliceStable(paths, func(i, j int) bool {
			li := pathLatency(paths[i])
			lj := pathLatency(paths[j])
			return li < lj
		})

	case "meta_latency_desc":
		sort.SliceStable(paths, func(i, j int) bool {
			li := pathLatency(paths[i])
			lj := pathLatency(paths[j])
			return li > lj
		})

	case "meta_bandwidth_asc":
		sort.SliceStable(paths, func(i, j int) bool {
			return pathBandwidth(paths[i]) < pathBandwidth(paths[j])
		})

	case "meta_bandwidth_desc":
		sort.SliceStable(paths, func(i, j int) bool {
			return pathBandwidth(paths[i]) > pathBandwidth(paths[j])
		})
	}
}

// hopCount returns the number of interfaces (hops) in the path.
func hopCount(p pathpool.CachedPath) int {
	meta := p.Path.Metadata()
	if meta == nil {
		return 0
	}
	return len(meta.Interfaces)
}

// pathLatency returns the total latency of a path in milliseconds.
// Returns MaxInt64 if no latency data is available (sorts to the end for asc).
func pathLatency(p pathpool.CachedPath) int64 {
	meta := p.Path.Metadata()
	if meta == nil {
		return maxInt64
	}

	total := totalLatency(meta.Latency)
	if total < 0 {
		return maxInt64
	}

	return total.Milliseconds()
}

// pathBandwidth returns the minimum bandwidth along the path in kbit/s.
// Returns 0 if no bandwidth data is available.
func pathBandwidth(p pathpool.CachedPath) uint64 {
	meta := p.Path.Metadata()
	if meta == nil {
		return 0
	}
	return minBandwidth(meta.Bandwidth)
}

// shufflePaths randomly shuffles the path slice.
func shufflePaths(paths []pathpool.CachedPath) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(paths), func(i, j int) {
		paths[i], paths[j] = paths[j], paths[i]
	})
}

const maxInt64 = int64(^uint64(0) >> 1)
