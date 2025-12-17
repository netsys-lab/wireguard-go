package scion_paths

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

// getEnvIA helper to read IAs from environment or use default
func getEnvIA(key, defaultVal string) addr.IA {
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

func TestSciondRetrieverIntegration(t *testing.T) {
	// 1. Setup Retriever
	r, err := NewSciondRetriever()
	if err != nil {
		t.Skipf("skipping integration test: cannot connect to sciond: %v", err)
	}

	// 2. Configure Topology (defaults to your local setup)
	src := getEnvIA("SCION_TEST_SRC_IA", "1-ff00:0:110")
	dst := getEnvIA("SCION_TEST_DST_IA", "1-ff00:0:111")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 3. Execute Fetch
	t.Logf("Fetching paths from %s to %s...", src, dst)
	paths, err := r.RetrievePaths(ctx, src, dst)
	if err != nil {
		t.Fatalf("RetrievePaths returned error: %v", err)
	}

	if len(paths) == 0 {
		t.Fatalf("RetrievePaths returned 0 paths. Check your SCION topology or src/dst IAs.")
	}

	t.Logf("Successfully retrieved %d paths", len(paths))

	// 4. Sanity Check the Data
	for i, p := range paths {
		meta := p.Metadata()
		if meta == nil {
			t.Errorf("Path %d has nil Metadata", i)
			continue
		}

		// Check MTU
		if meta.MTU == 0 {
			t.Errorf("Path %d has 0 MTU, expected > 0", i)
		}

		// Check Interfaces
		if len(meta.Interfaces) == 0 {
			t.Errorf("Path %d has 0 interfaces", i)
		}

		// Check Expiry
		if time.Now().After(meta.Expiry) {
			t.Errorf("Path %d is already expired! (Expiry: %s)", i, meta.Expiry)
		}

		// Check NextHop (Critical for WireGuard)
		if p.UnderlayNextHop() == nil {
			t.Errorf("Path %d has nil NextHop (Border Router address missing)", i)
		}

		t.Logf("[OK] Path %d: Hops=%d MTU=%d NextHop=%v", i, len(meta.Interfaces), meta.MTU, p.UnderlayNextHop())
	}
}

// TestSciondRetrieverTimeout verifies that the retriever respects context cancellation
func TestSciondRetrieverTimeout(t *testing.T) {
	r, err := NewSciondRetriever()
	if err != nil {
		t.Skip("skipping timeout test: daemon not available")
	}

	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	// Create a context that cancels immediately (0 timeout)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	_, err = r.RetrievePaths(ctx, src, dst)

	if err == nil {
		t.Fatal("Expected timeout error, got nil")
	}

	t.Logf("Correctly received error on timeout: %v", err)
}
