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

func TestPathPoolRefreshErrorIsVisibleInSnapshot(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	mockErr := errors.New("mock retriever failed")

	mock := &MockRetriever{
		ErrToReturn: mockErr,
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	_, err := pp.Get(context.Background(), src, dst)
	if !errors.Is(err, ErrPathPending) {
		t.Fatalf("expected ErrPathPending, got %v", err)
	}

	waitUntil(t, time.Second, func() bool {
		pair := pp.SnapshotFor(src, dst)
		return pair.LastError != ""
	})

	pair := pp.SnapshotFor(src, dst)

	if pair.AvailablePaths != 0 {
		t.Fatalf("expected 0 available paths, got %d", pair.AvailablePaths)
	}

	if pair.LastError == "" {
		t.Fatal("expected LastError to be set")
	}

	if pair.InFlight {
		t.Fatal("expected InFlight to be false after failed refresh")
	}
}

func TestPathPoolNoPathsResultIsVisibleInSnapshot(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	mock := &MockRetriever{
		PathsToReturn: []snet.Path{},
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	_, err := pp.Get(context.Background(), src, dst)
	if !errors.Is(err, ErrPathPending) {
		t.Fatalf("expected ErrPathPending, got %v", err)
	}

	waitUntil(t, time.Second, func() bool {
		pair := pp.SnapshotFor(src, dst)
		return pair.LastError != ""
	})

	pair := pp.SnapshotFor(src, dst)

	if pair.LastError != ErrNoPaths.Error() {
		t.Fatalf("expected LastError %q, got %q", ErrNoPaths.Error(), pair.LastError)
	}

	if pair.InFlight {
		t.Fatal("expected InFlight to be false after no-path refresh")
	}
}

func TestPathPoolExpirySoonTriggersBackgroundRefresh(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	soonExpiry := time.Now().Add(5 * time.Second)
	freshExpiry := time.Now().Add(1 * time.Hour)

	oldPath := createPath(src, dst, 1, soonExpiry, "127.0.0.1", 30041)
	freshPath := createPath(src, dst, 2, freshExpiry, "127.0.0.2", 30042)

	mock := &MockRetriever{
		PathsToReturn: []snet.Path{freshPath},
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	pp.Add(src, dst, []snet.Path{oldPath})

	paths, err := pp.Get(context.Background(), src, dst)
	if err != nil {
		t.Fatalf("expected valid old path to be returned immediately, got err=%v", err)
	}

	if len(paths) != 1 {
		t.Fatalf("expected 1 valid path, got %d", len(paths))
	}

	waitUntil(t, time.Second, func() bool {
		return mock.Calls() == 1
	})

	waitUntil(t, time.Second, func() bool {
		paths, err := pp.Get(context.Background(), src, dst)
		if err != nil || len(paths) != 1 || paths[0].NextHop == nil {
			return false
		}
		return paths[0].NextHop.String() == "127.0.0.2:30042"
	})
}

func TestPathPoolPrefetchAsync(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	expiry := time.Now().Add(1 * time.Hour)
	retrievedPath := createPath(src, dst, 123, expiry, "127.0.0.123", 50123)

	mock := &MockRetriever{
		PathsToReturn: []snet.Path{retrievedPath},
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	pp.PrefetchAsync([]IAPair{
		{Src: src, Dst: dst},
	})

	waitUntil(t, time.Second, func() bool {
		paths, err := pp.Get(context.Background(), src, dst)
		return err == nil && len(paths) == 1
	})
}

// --- Refresh correlation ID tests ---

func TestRefreshAsync_FirstRequestStartsRefreshIDX(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	mock := &MockRetriever{
		PathsToReturn: []snet.Path{},
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	status := pp.RefreshAsync(src, dst, "test")

	if !status.Started {
		t.Error("expected first RefreshAsync to start a new refresh")
	}
	if status.ID == 0 {
		t.Error("expected non-zero refresh ID")
	}
}

func TestRefreshAsync_SecondRequestJoinsSameRefreshID(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	mock := &MockRetriever{
		PathsToReturn: []snet.Path{},
		Delay:         200 * time.Millisecond,
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	status1 := pp.RefreshAsync(src, dst, "test")
	status2 := pp.RefreshAsync(src, dst, "test")

	if !status1.Started {
		t.Error("expected first to start")
	}
	if status2.Started {
		t.Error("expected second to join (not start)")
	}
	if status1.ID != status2.ID {
		t.Errorf("expected same refresh ID: status1.ID=%d status2.ID=%d", status1.ID, status2.ID)
	}
}

func TestRefreshAsync_DifferentIAPairGetsDifferentID(t *testing.T) {
	src1, _ := addr.ParseIA("1-ff00:0:110")
	dst1, _ := addr.ParseIA("1-ff00:0:111")
	src2, _ := addr.ParseIA("1-ff00:0:220")
	dst2, _ := addr.ParseIA("1-ff00:0:221")

	mock := &MockRetriever{
		PathsToReturn: []snet.Path{},
		Delay:         200 * time.Millisecond,
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	status1 := pp.RefreshAsync(src1, dst1, "test")
	status2 := pp.RefreshAsync(src2, dst2, "test")

	if !status1.Started || !status2.Started {
		t.Error("both should start since they are different IA pairs")
	}
	if status1.ID == status2.ID {
		t.Errorf("different IA pairs should get different refresh IDs: both got %d", status1.ID)
	}
}

func TestRefreshAsync_InflightDeletedOnSuccess(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	expiry := time.Now().Add(1 * time.Hour)
	retrievedPath := createPath(src, dst, 1, expiry, "127.0.0.1", 30041)

	mock := &MockRetriever{
		PathsToReturn: []snet.Path{retrievedPath},
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	pp.RefreshAsync(src, dst, "test")

	// Wait for refresh to complete.
	waitUntil(t, time.Second, func() bool {
		pair := pp.SnapshotFor(src, dst)
		return pair.AvailablePaths > 0
	})

	// Inflight entry should be cleaned up.
	pp.mu.Lock()
	inflight := pp.inflight[key{src: src, dst: dst}]
	pp.mu.Unlock()

	if inflight != nil {
		t.Error("inflight entry should be deleted after successful refresh")
	}
}

func TestRefreshAsync_InflightDeletedOnError(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	mock := &MockRetriever{
		ErrToReturn: errors.New("mock error"),
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	pp.RefreshAsync(src, dst, "test")

	// Wait for refresh to complete.
	waitUntil(t, time.Second, func() bool {
		pair := pp.SnapshotFor(src, dst)
		return pair.LastError != ""
	})

	// Inflight entry should be cleaned up.
	pp.mu.Lock()
	inflight := pp.inflight[key{src: src, dst: dst}]
	pp.mu.Unlock()

	if inflight != nil {
		t.Error("inflight entry should be deleted after error")
	}
}

func TestRefreshAsync_InflightDeletedOnNoPaths(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	mock := &MockRetriever{
		PathsToReturn: []snet.Path{},
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	pp.RefreshAsync(src, dst, "test")

	// Wait for refresh to complete.
	waitUntil(t, time.Second, func() bool {
		pair := pp.SnapshotFor(src, dst)
		return pair.LastError == ErrNoPaths.Error()
	})

	// Inflight entry should be cleaned up.
	pp.mu.Lock()
	inflight := pp.inflight[key{src: src, dst: dst}]
	pp.mu.Unlock()

	if inflight != nil {
		t.Error("inflight entry should be deleted after no-paths result")
	}
}

func TestRefreshAsync_InflightDeletedOnTimeout(t *testing.T) {
	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	mock := &MockRetriever{
		Delay: 5 * time.Second,
	}

	pp := NewPathPool(mock)
	pp.queryTimeout = 50 * time.Millisecond
	defer pp.Close()

	pp.RefreshAsync(src, dst, "test")

	// Wait for timeout to trigger.
	waitUntil(t, time.Second, func() bool {
		pair := pp.SnapshotFor(src, dst)
		return pair.LastError != ""
	})

	// Inflight entry should be cleaned up after timeout.
	pp.mu.Lock()
	inflight := pp.inflight[key{src: src, dst: dst}]
	pp.mu.Unlock()

	if inflight != nil {
		t.Error("inflight entry should be deleted after timeout")
	}
}

func TestRefreshAsync_RefreshIDMonotonicallyIncreases(t *testing.T) {
	src1, _ := addr.ParseIA("1-ff00:0:110")
	dst1, _ := addr.ParseIA("1-ff00:0:111")
	src2, _ := addr.ParseIA("1-ff00:0:220")
	dst2, _ := addr.ParseIA("1-ff00:0:221")

	mock := &MockRetriever{
		PathsToReturn: []snet.Path{},
		Delay:         200 * time.Millisecond,
	}

	pp := NewPathPool(mock)
	defer pp.Close()

	s1 := pp.RefreshAsync(src1, dst1, "test")
	s2 := pp.RefreshAsync(src2, dst2, "test")

	if s2.ID <= s1.ID {
		t.Errorf("refresh IDs should increase: s1.ID=%d s2.ID=%d", s1.ID, s2.ID)
	}
}
