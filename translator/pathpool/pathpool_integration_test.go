//go:build integration
// +build integration

package pathpool

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"golang.zx2c4.com/wireguard/translator/daemon"
)

// getEnvIAHelper reads an IA from an environment variable or falls back to a default.
func getEnvIAHelper(key, defaultVal string) addr.IA {
	val := os.Getenv(key)
	if val == "" {
		val = defaultVal
	}

	ia, err := addr.ParseIA(val)
	if err != nil {
		panic("invalid IA in env var " + key + ": " + val)
	}

	return ia
}

// waitForRealPaths polls the PathPool until the async refresh worker has
// populated the cache with real paths from the daemon.
func waitForRealPaths(t *testing.T, pp *PathPool, src, dst addr.IA, timeout time.Duration) []CachedPath {
	t.Helper()

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		paths, err := pp.Get(context.Background(), src, dst)
		if err == nil && len(paths) > 0 {
			return paths
		}

		if err != nil && !errors.Is(err, ErrPathPending) {
			t.Fatalf("unexpected error while waiting for paths: %v", err)
		}

		time.Sleep(100 * time.Millisecond)
	}

	snapshot := pp.SnapshotFor(src, dst)
	t.Fatalf(
		"paths did not become available within %v; inFlight=%v lastError=%q availablePaths=%d",
		timeout,
		snapshot.InFlight,
		snapshot.LastError,
		snapshot.AvailablePaths,
	)

	return nil
}

// integration test against real SCION daemon / retriever.
func TestPathPoolIntegration_RealDaemon(t *testing.T) {
	retriever, err := daemon.NewSciondRetriever()
	if err != nil {
		t.Skipf("Skipping integration test: cannot connect to SCION daemon/retriever: %v", err)
	}

	pp := NewPathPool(retriever)
	defer pp.Close()

	src := getEnvIAHelper("SCION_TEST_SRC_IA", "1-ff00:0:110")
	dst := getEnvIAHelper("SCION_TEST_DST_IA", "1-ff00:0:111")

	t.Logf("Integration Test: fetching paths from %s to %s via daemon", src, dst)

	start := time.Now()

	// First call should not block for the real path lookup anymore.
	// It should schedule the async refresh and return ErrPathPending.
	paths, err := pp.Get(context.Background(), src, dst)
	if !errors.Is(err, ErrPathPending) {
		t.Fatalf("expected first Get to return ErrPathPending, got paths=%d err=%v", len(paths), err)
	}

	if len(paths) != 0 {
		t.Fatalf("expected first Get to return no paths, got %d", len(paths))
	}

	t.Logf("First Get returned ErrPathPending after %v; waiting for async refresh", time.Since(start))

	// Now wait until the async refresh worker has fetched and cached paths.
	paths = waitForRealPaths(t, pp, src, dst, 10*time.Second)
	duration := time.Since(start)

	t.Logf("SUCCESS: async refresh produced %d paths in %v", len(paths), duration)

	for i, p := range paths {
		if p.NextHop == nil {
			t.Errorf("Path %d has nil NextHop; WireGuard cannot send without this", i)
		}

		if !p.Expiry.IsZero() && p.Expiry.Before(time.Now()) {
			t.Errorf("Path %d is expired", i)
		}

		fp := p.Fingerprint
		if len(fp) > 8 {
			fp = fp[:8]
		}

		t.Logf("  [%d] Fingerprint: %s... NextHop: %s Expiry: %s", i, fp, p.NextHop, p.Expiry)
	}

	// Cached fetch should now return immediately.
	startCache := time.Now()
	pathsCached, err := pp.Get(context.Background(), src, dst)
	durationCache := time.Since(startCache)

	if err != nil {
		t.Fatalf("cached Get failed after async refresh: %v", err)
	}

	if len(pathsCached) != len(paths) {
		t.Errorf(
			"cache inconsistency: first async result got %d paths, cached Get got %d",
			len(paths),
			len(pathsCached),
		)
	}

	t.Logf("SUCCESS: cached retrieval returned %d paths in %v", len(pathsCached), durationCache)
}
