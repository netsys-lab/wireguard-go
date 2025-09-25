package scion_paths

import (
	"context"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

func TestSciondRetrieverIntegration(t *testing.T) {
	r, err := NewSciondRetriever()
	if err != nil {
		t.Skipf("cannot connect to sciond: %v", err) // skip if not available
	}

	src, _ := addr.ParseIA("1-ff00:0:110")
	dst, _ := addr.ParseIA("1-ff00:0:111")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	paths, err := r.RetrievePaths(ctx, src, dst)
	if err != nil {
		t.Fatalf("RetrievePaths failed: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("no paths found between %s and %s", src, dst)
	}

	t.Logf("Retrieved %d paths", len(paths))
	for i, p := range paths {
		t.Logf("Path %d: MTU=%d Interfaces=%d Exp=%s", i, p.MTU, p.Interfaces, p.Expiration)
	}
}
