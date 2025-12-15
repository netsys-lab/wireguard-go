package scion_paths

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

// --- Helpers & Mocks ---

// MockRetriever implements PathRetriever for testing
type MockRetriever struct {
	PathsToReturn []snet.Path
	ErrToReturn   error
	CallCount     int
}

func (m *MockRetriever) RetrievePaths(ctx context.Context, src, dst addr.IA) ([]snet.Path, error) {
	m.CallCount++
	return m.PathsToReturn, m.ErrToReturn
}

// createPath helper
// Added 'id' parameter to ensure unique fingerprints for testing multiple paths
func createPath(src, dst addr.IA, id uint64, expiry time.Time, nextHopIP string, nextHopPort int) snet.Path {
	meta := snet.PathMetadata{
		Interfaces: []snet.PathInterface{
			{IA: dst, ID: iface.ID(id)}, // Distinct ID = Distinct Fingerprint
		},
		Expiry: expiry,
	}

	// Use ParseIP to mock the address structure
	nextHop := &net.UDPAddr{
		IP:   net.ParseIP(nextHopIP),
		Port: nextHopPort,
	}

	return path.Path{
		NextHop: nextHop,
		Meta:    meta,
		Src:     src,
		Dst:     dst,
	}
}

// getEnvIAHelper reads IAs from environment or uses a default (for local topology testing)
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

// --- Unit Tests (Mocked) ---

func TestPathPoolAddAndGet(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	expiry := time.Now().Add(1 * time.Hour)
	mockPath := createPath(src, dst, 1, expiry, "127.0.0.1", 30041)

	// Pass nil retriever for manual caching tests
	pp := NewPathPool(nil)
	defer pp.Close()

	pp.Add(src, dst, []snet.Path{mockPath})

	ctx := context.Background()
	cached, err := pp.Get(ctx, src, dst)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if len(cached) == 0 {
		t.Fatal("no paths found in cache")
	}

	if cached[0].Fingerprint == "" {
		t.Error("fingerprint should not be empty")
	}

	t.Logf("Successfully retrieved path with fingerprint: %s", cached[0].Fingerprint)
}

func TestPathPoolMultiplePaths(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	expiry := time.Now().Add(1 * time.Hour)

	// Use ID 1 and ID 2 to ensure they are treated as distinct paths
	path1 := createPath(src, dst, 1, expiry, "127.0.0.1", 30041)
	path2 := createPath(src, dst, 2, expiry.Add(10*time.Minute), "127.0.0.2", 40042)

	pp := NewPathPool(nil)
	defer pp.Close()

	pp.Add(src, dst, []snet.Path{path1, path2})

	ctx := context.Background()
	cached, err := pp.Get(ctx, src, dst)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if len(cached) != 2 {
		t.Fatalf("expected 2 cached paths, got %d", len(cached))
	}

	t.Logf("Successfully cached %d distinct paths", len(cached))
}

func TestPathPoolExpiredPaths(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	expiry := time.Now().Add(-1 * time.Hour)
	expiredPath := createPath(src, dst, 10, expiry, "127.0.0.3", 50043)

	pp := NewPathPool(nil)
	defer pp.Close()

	pp.Add(src, dst, []snet.Path{expiredPath})

	ctx := context.Background()
	cached, err := pp.Get(ctx, src, dst)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if len(cached) != 0 {
		t.Fatalf("expected 0 cached paths (expired), got %d", len(cached))
	}
}

func TestPathPoolReadThrough(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	expiry := time.Now().Add(1 * time.Hour)
	retrievedPath := createPath(src, dst, 99, expiry, "127.0.0.99", 50099)

	// Setup mock to return one path
	mock := &MockRetriever{
		PathsToReturn: []snet.Path{retrievedPath},
	}

	// Initialize pool with the MockRetriever
	pp := NewPathPool(mock)
	defer pp.Close()

	// 1. First Get: Should be empty in cache, so it hits the mock retriever
	ctx := context.Background()
	paths, err := pp.Get(ctx, src, dst)
	if err != nil {
		t.Fatalf("Get failed during read-through: %v", err)
	}

	if mock.CallCount != 1 {
		t.Errorf("Expected retriever to be called 1 time, got %d", mock.CallCount)
	}
	if len(paths) != 1 {
		t.Fatalf("Expected 1 path, got %d", len(paths))
	}

	// 2. Second Get: Should hit the cache
	paths2, err := pp.Get(ctx, src, dst)
	if err != nil {
		t.Fatalf("Second Get failed: %v", err)
	}
	if len(paths2) != 1 {
		t.Fatalf("Expected 1 path, got %d", len(paths2))
	}
	if mock.CallCount != 1 {
		t.Errorf("Expected retriever CallCount to stay 1 (cache hit), but got %d", mock.CallCount)
	}

	t.Log("Successfully verified Read-Through caching behavior")
}

// --- Integration Test (Real Daemon) ---

// TestPathPoolIntegration_RealDaemon connects to a real local SCION daemon.
// Set SCION_TEST_SRC_IA and SCION_TEST_DST_IA env vars to match your topology.
func TestPathPoolIntegration_RealDaemon(t *testing.T) {
	// 1. Setup Real Retriever
	retriever, err := NewSciondRetriever()
	if err != nil {
		t.Skipf("Skipping integration test: cannot connect to sciond: %v", err)
	}

	// 2. Initialize Pool with Real Retriever
	pp := NewPathPool(retriever)
	defer pp.Close()

	// 3. Define Topology
	src := getEnvIAHelper("SCION_TEST_SRC_IA", "1-ff00:0:110")
	dst := getEnvIAHelper("SCION_TEST_DST_IA", "1-ff00:0:111")

	t.Logf("Integration Test: Fetching paths from %s to %s via Daemon...", src, dst)

	// 4. Perform Get (Should Trigger Network Fetch)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

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

	// 5. Verify Path Content
	for i, p := range paths {
		if p.NextHop == nil {
			t.Errorf("Path %d has nil NextHop! WireGuard cannot work without this.", i)
		}
		if p.Expiry.Before(time.Now()) {
			t.Errorf("Path %d is expired.", i)
		}
		t.Logf("  [%d] Fingerprint: %s... NextHop: %s", i, p.Fingerprint[:8], p.NextHop)
	}

	// 6. Verify Caching (Subsequent call should be instant)
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
