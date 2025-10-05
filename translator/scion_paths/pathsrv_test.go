package scion_paths

import (
	"context"
	"testing"
	"time"
)

func TestDirectPathRetrieverIntegration(t *testing.T) {
	// Replace with your Path Server gRPC address in the local topology
	psAddr := "127.0.0.11:31000"

	r, err := NewDirectPathRetriever(psAddr)
	if err != nil {
		t.Skipf("cannot connect to Path Server at %s: %v", psAddr, err)
	}

	srcIA := "1-ff00:0:110"
	dstIA := "1-ff00:0:111"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	paths, err := r.RetrievePaths(ctx, srcIA, dstIA)
	if err != nil {
		t.Fatalf("RetrievePaths failed: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("no paths found between %s and %s", srcIA, dstIA)
	}

	t.Logf("Retrieved %d paths", len(paths))
	for i, p := range paths {
		t.Logf("Path %d: MTU=%d Interfaces=%d Exp=%s Raw=%x",
			i, p.MTU, p.Interfaces, p.Expiration, p.Raw)
	}
}
