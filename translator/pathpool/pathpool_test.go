package pathpool

import (
	"context"
	"net"
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
