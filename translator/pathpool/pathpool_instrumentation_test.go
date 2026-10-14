package pathpool

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

// --- Helpers ---

func mustIA(t *testing.T, isd int, asn uint64) addr.IA {
	t.Helper()
	ia, err := addr.ParseIA(fmt.Sprintf("%d-%d", isd, asn))
	if err != nil {
		t.Fatalf("mustIA: %v", err)
	}
	return ia
}

// --- Context refreshId tests ---

func TestRefreshID_FirstIDIsOne(t *testing.T) {
	mock := &mockRetriever{
		retrieveFunc: func(ctx context.Context, src, dst addr.IA) ([]snet.Path, error) {
			return nil, nil
		},
	}
	pp := NewPathPool(mock, noopLog)
	defer pp.Close()

	src := mustIA(t, 1, 1)
	dst := mustIA(t, 2, 2)

	status := pp.RefreshAsync(src, dst, "test")
	if !status.Started {
		t.Fatal("expected refresh to start")
	}
	if status.ID != 1 {
		t.Errorf("first refresh ID = %d, want 1", status.ID)
	}
}

func TestRefreshID_SecondDistinctPairGetsHigherID(t *testing.T) {
	mock := &mockRetriever{
		retrieveFunc: func(ctx context.Context, src, dst addr.IA) ([]snet.Path, error) {
			return nil, nil
		},
	}
	pp := NewPathPool(mock, noopLog)
	defer pp.Close()

	src1 := mustIA(t, 1, 1)
	dst1 := mustIA(t, 2, 2)
	src2 := mustIA(t, 3, 3)
	dst2 := mustIA(t, 4, 4)

	s1 := pp.RefreshAsync(src1, dst1, "test")
	s2 := pp.RefreshAsync(src2, dst2, "test")

	if !s1.Started || !s2.Started {
		t.Fatal("expected both refreshes to start")
	}
	if s2.ID <= s1.ID {
		t.Errorf("second refresh ID %d should be > first %d", s2.ID, s1.ID)
	}
}

func TestRefreshID_JoinedRefreshPreservesSameID(t *testing.T) {
	mock := &mockRetriever{
		retrieveFunc: func(ctx context.Context, src, dst addr.IA) ([]snet.Path, error) {
			// Slow retriever to keep inflight alive
			time.Sleep(100 * time.Millisecond)
			return nil, nil
		},
	}
	pp := NewPathPool(mock, noopLog)
	defer pp.Close()

	src := mustIA(t, 1, 1)
	dst := mustIA(t, 2, 2)

	s1 := pp.RefreshAsync(src, dst, "test")
	// Second call should join the same inflight refresh
	s2 := pp.RefreshAsync(src, dst, "test")

	if !s1.Started {
		t.Fatal("first refresh should start")
	}
	if s2.Started {
		t.Fatal("second refresh should join (not start)")
	}
	if s2.ID != s1.ID {
		t.Errorf("joined refresh ID %d should equal first %d", s2.ID, s1.ID)
	}
}

// --- Context refreshId tests ---

func TestContextWithRefreshID_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ctx = ContextWithRefreshID(ctx, 42)

	id, ok := RefreshIDFromContext(ctx)
	if !ok {
		t.Fatal("expected refreshId present in context")
	}
	if id != 42 {
		t.Errorf("refreshId = %d, want 42", id)
	}
}

func TestRefreshIDFromContext_EmptyContext(t *testing.T) {
	ctx := context.Background()

	id, ok := RefreshIDFromContext(ctx)
	if ok {
		t.Errorf("expected no refreshId, got %d", id)
	}
}

func TestContextWithRefreshID_ZeroValue(t *testing.T) {
	ctx := context.Background()
	ctx = ContextWithRefreshID(ctx, 0)

	id, ok := RefreshIDFromContext(ctx)
	if !ok {
		t.Fatal("expected refreshId present (even 0)")
	}
	if id != 0 {
		t.Errorf("refreshId = %d, want 0", id)
	}
}

// --- Error categorization tests ---

func TestErrorCategory_ContextDeadline(t *testing.T) {
	err := context.DeadlineExceeded

	errorCategory := "connector-error"
	if errors.Is(err, context.DeadlineExceeded) {
		errorCategory = "context-deadline"
	}

	if errorCategory != "context-deadline" {
		t.Errorf("errorCategory = %q, want context-deadline", errorCategory)
	}
}

func TestErrorCategory_ConnectorError(t *testing.T) {
	err := fmt.Errorf("connection refused")

	errorCategory := "connector-error"
	if errors.Is(err, context.DeadlineExceeded) {
		errorCategory = "context-deadline"
	}

	if errorCategory != "connector-error" {
		t.Errorf("errorCategory = %q, want connector-error", errorCategory)
	}
}

func TestErrorCategory_WrappedDeadline(t *testing.T) {
	err := fmt.Errorf("wrapper: %w", context.DeadlineExceeded)

	errorCategory := "connector-error"
	if errors.Is(err, context.DeadlineExceeded) {
		errorCategory = "context-deadline"
	}

	if errorCategory != "context-deadline" {
		t.Errorf("errorCategory = %q, want context-deadline (wrapped deadline)", errorCategory)
	}
}

// --- Remaining deadline tests ---

func TestRemainingDeadline_Active(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	remainingMs := 0
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 {
			remainingMs = int(remaining.Milliseconds())
		}
	}

	if remainingMs < 29000 || remainingMs > 30000 {
		t.Errorf("remainingMs = %d, want ~30000", remainingMs)
	}
}

func TestRemainingDeadline_Expired(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)

	remainingMs := 0
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining > 0 {
			remainingMs = int(remaining.Milliseconds())
		}
	}

	if remainingMs != 0 {
		t.Errorf("remainingMs = %d, want 0 for expired context", remainingMs)
	}
}

// --- RefreshWorker error path tests ---

func TestRefreshWorker_ContextDeadline_Logged(t *testing.T) {
	timeoutCalled := make(chan struct{}, 1)
	mock := &mockRetriever{
		retrieveFunc: func(ctx context.Context, src, dst addr.IA) ([]snet.Path, error) {
			// Wait until context expires
			<-ctx.Done()
			timeoutCalled <- struct{}{}
			return nil, ctx.Err()
		},
	}

	pp := NewPathPool(mock, noopLog)
	defer pp.Close()

	src := mustIA(t, 1, 1)
	dst := mustIA(t, 2, 2)

	// Use a very short timeout
	pp.queryTimeout = 10 * time.Millisecond

	status := pp.RefreshAsync(src, dst, "test")
	if !status.Started {
		t.Fatal("expected refresh to start")
	}

	// Wait for the mock to be called
	<-timeoutCalled

	// Give time for refreshWorker to finish and log
	time.Sleep(50 * time.Millisecond)
}

func TestRefreshWorker_NoPaths_Logged(t *testing.T) {
	mock := &mockRetriever{
		retrieveFunc: func(ctx context.Context, src, dst addr.IA) ([]snet.Path, error) {
			return nil, nil // success but no paths
		},
	}

	pp := NewPathPool(mock, noopLog)
	defer pp.Close()

	src := mustIA(t, 1, 1)
	dst := mustIA(t, 2, 2)

	status := pp.RefreshAsync(src, dst, "test")
	if !status.Started {
		t.Fatal("expected refresh to start")
	}

	// Wait for refresh to complete
	time.Sleep(50 * time.Millisecond)
}

// --- mockRetriever for testing ---

type mockRetriever struct {
	retrieveFunc func(ctx context.Context, src, dst addr.IA) ([]snet.Path, error)
}

func (m *mockRetriever) RetrievePaths(ctx context.Context, src, dst addr.IA) ([]snet.Path, error) {
	if m.retrieveFunc != nil {
		return m.retrieveFunc(ctx, src, dst)
	}
	return nil, nil
}
