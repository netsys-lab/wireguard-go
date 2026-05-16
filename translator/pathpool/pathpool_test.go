package pathpool

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

// --- Helpers & Mocks ---

// MockRetriever implements PathRetriever for testing.
// It is async-safe because RetrievePaths can be called from refreshWorker goroutines.
type MockRetriever struct {
	PathsToReturn []snet.Path
	ErrToReturn   error
	Delay         time.Duration

	CallCount atomic.Int32
}

func (m *MockRetriever) RetrievePaths(ctx context.Context, src, dst addr.IA) ([]snet.Path, error) {
	m.CallCount.Add(1)

	if m.Delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(m.Delay):
		}
	}

	return m.PathsToReturn, m.ErrToReturn
}

func (m *MockRetriever) Calls() int {
	return int(m.CallCount.Load())
}

// createPath helper.
// The id parameter makes fingerprints distinct for tests with multiple paths.
func createPath(src, dst addr.IA, id uint64, expiry time.Time, nextHopIP string, nextHopPort int) snet.Path {
	meta := snet.PathMetadata{
		Interfaces: []snet.PathInterface{
			{IA: dst, ID: iface.ID(id)},
		},
		Expiry: expiry,
	}

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

func waitUntil(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("condition not met within %v", timeout)
}

// --- Unit Tests (Mocked) ---

func TestPathPoolAddAndGet(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	expiry := time.Now().Add(1 * time.Hour)
	mockPath := createPath(src, dst, 1, expiry, "127.0.0.1", 30041)

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

func TestPathPoolExpiredPathsReturnPending(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	expiry := time.Now().Add(-1 * time.Hour)
	expiredPath := createPath(src, dst, 10, expiry, "127.0.0.3", 50043)

	pp := NewPathPool(nil)
	defer pp.Close()

	pp.Add(src, dst, []snet.Path{expiredPath})

	ctx := context.Background()
	cached, err := pp.Get(ctx, src, dst)

	if !errors.Is(err, ErrPathPending) {
		t.Fatalf("expected ErrPathPending, got paths=%d err=%v", len(cached), err)
	}

	if len(cached) != 0 {
		t.Fatalf("expected 0 cached paths, got %d", len(cached))
	}
}

func TestPathPoolCacheMissTriggersAsyncRefresh(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	expiry := time.Now().Add(1 * time.Hour)
	retrievedPath := createPath(src, dst, 99, expiry, "127.0.0.99", 50099)

	mock := &MockRetriever{
		PathsToReturn: []snet.Path{retrievedPath},
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	ctx := context.Background()

	paths, err := pp.Get(ctx, src, dst)
	if !errors.Is(err, ErrPathPending) {
		t.Fatalf("expected ErrPathPending on first Get, got paths=%d err=%v", len(paths), err)
	}

	if len(paths) != 0 {
		t.Fatalf("expected no paths on first Get, got %d", len(paths))
	}

	waitUntil(t, time.Second, func() bool {
		return mock.Calls() == 1
	})

	waitUntil(t, time.Second, func() bool {
		paths, err := pp.Get(ctx, src, dst)
		return err == nil && len(paths) == 1
	})

	paths, err = pp.Get(ctx, src, dst)
	if err != nil {
		t.Fatalf("expected cached paths after async refresh, got err=%v", err)
	}

	if len(paths) != 1 {
		t.Fatalf("expected 1 cached path after refresh, got %d", len(paths))
	}

	if mock.Calls() != 1 {
		t.Fatalf("expected retriever to be called once, got %d", mock.Calls())
	}

	t.Log("Successfully verified async cache-miss refresh behavior")
}

func TestPathPoolInflightDeduplicatesRefreshes(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	expiry := time.Now().Add(1 * time.Hour)
	retrievedPath := createPath(src, dst, 42, expiry, "127.0.0.42", 50042)

	mock := &MockRetriever{
		PathsToReturn: []snet.Path{retrievedPath},
		Delay:         100 * time.Millisecond,
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	ctx := context.Background()

	for i := 0; i < 3; i++ {
		paths, err := pp.Get(ctx, src, dst)
		if !errors.Is(err, ErrPathPending) {
			t.Fatalf("expected ErrPathPending on Get %d, got paths=%d err=%v", i, len(paths), err)
		}
	}

	waitUntil(t, time.Second, func() bool {
		return mock.Calls() == 1
	})

	waitUntil(t, time.Second, func() bool {
		paths, err := pp.Get(ctx, src, dst)
		return err == nil && len(paths) == 1
	})

	if mock.Calls() != 1 {
		t.Fatalf("expected only one in-flight refresh, got %d calls", mock.Calls())
	}
}

func TestPathPoolRefreshCallbackFiresOnSuccess(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	expiry := time.Now().Add(1 * time.Hour)
	retrievedPath := createPath(src, dst, 77, expiry, "127.0.0.77", 50077)

	mock := &MockRetriever{
		PathsToReturn: []snet.Path{retrievedPath},
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	done := make(chan struct{})

	pp.SetRefreshCallback(func(cbSrc, cbDst addr.IA) {
		if cbSrc != src || cbDst != dst {
			t.Errorf("callback IA mismatch: got %s -> %s", cbSrc, cbDst)
		}
		close(done)
	})

	_, err := pp.Get(context.Background(), src, dst)
	if !errors.Is(err, ErrPathPending) {
		t.Fatalf("expected ErrPathPending, got %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("refresh callback was not called")
	}
}
