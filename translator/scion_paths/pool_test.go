package scion_paths

import (
	"context"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

func TestPathPoolIntegration(t *testing.T) {
	retriever, err := NewSciondRetriever()
	if err != nil {
		t.Skipf("cannot connect to sciond: %v", err)
	}

	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	paths, err := retriever.RetrievePaths(ctx, src, dst)
	if err != nil {
		t.Fatalf("failed to retrieve paths: %v", err)
	}
	if len(paths) == 0 {
		t.Skip("no available SCION paths to test")
	}

	// Initialize PathPool and add one path
	pp := NewPathPool()
	pp.Add(src, dst, []snet.Path{paths[0]})

	// Retrieve it again
	cached, err := pp.Get(ctx, src, dst)
	if err != nil {
		t.Fatalf("cache get failed: %v", err)
	}
	if len(cached) == 0 {
		t.Fatalf("no paths found in cache")
	}

	t.Logf("Cached %d path(s). First fingerprint: %s", len(cached), cached[0].Fingerprint)
	if cached[0].Path == nil {
		t.Fatalf("cached path object is nil")
	}
}
