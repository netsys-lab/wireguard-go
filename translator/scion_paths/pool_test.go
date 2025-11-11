package scion_paths

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

func createPath(src, dst addr.IA, expiry time.Time, nextHopIP string, nextHopPort int) snet.Path {
	// Create a dummy raw path (empty, but satisfies snet.DataplanePath)
	// empty bytes, can be replaced with real path bytes

	// Build the metadata
	meta := snet.PathMetadata{
		Interfaces: []snet.PathInterface{
			{IA: dst, ID: 1}, // single interface, ID=1
		},
		Expiry: expiry,
	}

	// Build the next-hop UDP address
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

func TestPathPoolAddAndGet(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	// Create a mock path that expires in 1 hour
	expiry := time.Now().Add(1 * time.Hour)
	mockPath := createPath(src, dst, expiry, "ligma.test", 30041)

	// Initialize PathPool and add the mock path
	pp := NewPathPool()
	defer pp.Close()

	pp.Add(src, dst, []snet.Path{mockPath})

	// Retrieve the cached path
	ctx := context.Background()
	cached, err := pp.Get(ctx, src, dst)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if len(cached) == 0 {
		t.Fatal("no paths found in cache")
	}

	// Verify the cached path
	if cached[0].Src != src {
		t.Errorf("expected src %v, got %v", src, cached[0].Src)
	}
	if cached[0].Dst != dst {
		t.Errorf("expected dst %v, got %v", dst, cached[0].Dst)
	}
	if cached[0].Path == nil {
		t.Fatal("cached path object is nil")
	}
	if cached[0].Fingerprint == "" {
		t.Error("fingerprint should not be empty")
	}
	if cached[0].NextHop == nil {
		t.Error("NextHop should not be nil")
	}

	t.Logf("Successfully cached and retrieved path with fingerprint: %s", cached[0].Fingerprint)
}

func TestPathPoolMultiplePaths(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	// Create multiple mock paths
	expiry := time.Now().Add(1 * time.Hour)
	path1 := createPath(src, dst, expiry, "ligma.test", 30041)
	path2 := createPath(src, dst, expiry.Add(10*time.Minute), "example.test", 40042)

	pp := NewPathPool()
	defer pp.Close()

	// Add multiple paths
	pp.Add(src, dst, []snet.Path{path1, path2})

	ctx := context.Background()
	cached, err := pp.Get(ctx, src, dst)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if len(cached) != 2 {
		t.Fatalf("expected 2 cached paths, got %d", len(cached))
	}

	t.Logf("Successfully cached %d paths", len(cached))
}

func TestPathPoolExpiredPaths(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	// Create a path that's already expired
	expiry := time.Now().Add(-1 * time.Hour)
	expiredPath := createPath(src, dst, expiry, "expired.test", 50043)

	pp := NewPathPool()
	defer pp.Close()

	pp.Add(src, dst, []snet.Path{expiredPath})

	ctx := context.Background()
	cached, err := pp.Get(ctx, src, dst)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	// Should return no paths since they're all expired
	if len(cached) != 0 {
		t.Fatalf("expected 0 cached paths (expired), got %d", len(cached))
	}

	t.Log("Correctly filtered out expired paths")
}

func TestPathPoolNonExistent(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	pp := NewPathPool()
	defer pp.Close()

	ctx := context.Background()
	cached, err := pp.Get(ctx, src, dst)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if len(cached) != 0 {
		t.Fatalf("expected 0 cached paths for non-existent entry, got %d", len(cached))
	}

	t.Log("Correctly returned empty result for non-existent paths")
}
