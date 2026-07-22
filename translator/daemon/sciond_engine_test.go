package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"golang.zx2c4.com/wireguard/scionlog"
)

var noopLog = scionlog.NewLogger(
	func(string, ...any) {},
	func(string, ...any) {},
)

const (
	RealConfigDir = "/home/fidelioluc/scion/gen/ASff00_0_110/"

	RealSrcIA = "1-ff00:0:110"
	RealDstIA = "1-ff00:0:111"
)

func TestRetrievePaths_RealIntegration(t *testing.T) {

	retriever, err := NewSciondRetriever(RealConfigDir, noopLog)

	if err != nil {

		t.Skipf("Skipping integration test: Could not initialize engine (path: %s): %v", RealConfigDir, err)
		return
	}

	src, err := addr.ParseIA(RealSrcIA)
	if err != nil {
		t.Fatalf("Invalid Src IA: %v", err)
	}
	dst, err := addr.ParseIA(RealDstIA)
	if err != nil {
		t.Fatalf("Invalid Dst IA: %v", err)
	}

	// 3. Pfade abrufen
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Logf("Searching paths from %s to %s via embedded engine...", src, dst)

	paths, err := retriever.RetrievePaths(ctx, src, dst)

	if err != nil {
		t.Fatalf("RetrievePaths failed: %v", err)
	}

	if len(paths) == 0 {
		t.Fatal("RetrievePaths returned 0 paths! (Network might be unreachable or broken)")
	}

	t.Logf("SUCCESS! Found %d paths:", len(paths))
	for i, p := range paths {
		t.Logf("[%d] %v (MTU: %d)", i, p, p.Metadata().MTU)
	}
}
