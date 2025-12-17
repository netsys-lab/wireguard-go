//go:build integration
// +build integration

package pathpool

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"golang.zx2c4.com/wireguard/translator/daemon"
)

// read IA from env or default
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

// integration test against real sciond
func TestPathPoolIntegration_RealDaemon(t *testing.T) {
	// setup real retriever
	retriever, err := daemon.NewSciondRetriever()
	if err != nil {
		t.Skipf("Skipping integration test: cannot connect to sciond: %v", err)
	}

	// init pool
	pp := NewPathPool(retriever)
	defer pp.Close()

	// topology
	src := getEnvIAHelper("SCION_TEST_SRC_IA", "1-ff00:0:110")
	dst := getEnvIAHelper("SCION_TEST_DST_IA", "1-ff00:0:111")

	t.Logf("Integration Test: Fetching paths from %s to %s via Daemon...", src, dst)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// first fetch (network)
	start := time.Now()
	paths, err := pp.Get(ctx, src, dst)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Pool.Get failed with real daemon: %v", err)
	}

	if len(paths) == 0 {
		t.Fatalf("Pool.Get returned 0 paths. Check daemon connectivity.")
	}

	t.Logf("SUCCESS: Retrieved %d paths in %v", len(paths), duration)

	// sanity check paths
	for i, p := range paths {
		if p.NextHop == nil {
			t.Errorf("Path %d has nil NextHop! WireGuard cannot work without this.", i)
		}
		if p.Expiry.Before(time.Now()) {
			t.Errorf("Path %d is expired.", i)
		}
		t.Logf("  [%d] Fingerprint: %s... NextHop: %s", i, p.Fingerprint[:8], p.NextHop)
	}

	// cached fetch
	startCache := time.Now()
	pathsCached, err := pp.Get(ctx, src, dst)
	durationCache := time.Since(startCache)

	if err != nil {
		t.Fatalf("Subsequent cached Get failed: %v", err)
	}

	if len(pathsCached) != len(paths) {
		t.Errorf("Cache inconsistency: First fetch got %d, cached fetch got %d", len(paths), len(pathsCached))
	}

	t.Logf("SUCCESS: Cached retrieval took %v (Original took %v)", durationCache, duration)
}
