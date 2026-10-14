package header_parsing

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"

	"golang.zx2c4.com/wireguard/translator/pathpolicy"
	pathpool "golang.zx2c4.com/wireguard/translator/pathpool"
)

// Mock PathPool for testing
type mockPool struct {
	paths []pathpool.CachedPath
}

func (m *mockPool) Get(ctx context.Context, srcIA, dstIA addr.IA) ([]pathpool.CachedPath, error) {
	return m.paths, nil
}

func makeTestPathWithLatency(src, dst addr.IA, id uint64, latencyMs int64) pathpool.CachedPath {
	meta := snet.PathMetadata{
		Interfaces: []snet.PathInterface{
			{IA: src, ID: iface.ID(id)},
			{IA: dst, ID: iface.ID(id + 1)},
		},
		MTU:     1500,
		Expiry:  time.Now().Add(1 * time.Hour),
		Latency: []time.Duration{time.Duration(latencyMs) * time.Millisecond},
	}

	nextHop := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 30041,
	}

	sp := path.Path{
		NextHop: nextHop,
		Meta:    meta,
		Src:     src,
		Dst:     dst,
	}

	return pathpool.CachedPath{
		Src:         src,
		Dst:         dst,
		Path:        sp,
		NextHop:     nextHop,
		Fingerprint: "test-fp",
		Expiry:      meta.Expiry,
	}
}

func TestTranslatorSelectPathWithPolicy(t *testing.T) {
	srcIA, _ := addr.ParseIA("1-ff00:0:110")
	dstIA, _ := addr.ParseIA("1-ff00:0:111")

	// Create 3 mock paths with different latencies
	paths := []pathpool.CachedPath{
		makeTestPathWithLatency(srcIA, dstIA, 10, 100), // 100ms
		makeTestPathWithLatency(srcIA, dstIA, 20, 10),  // 10ms (best latency)
		makeTestPathWithLatency(srcIA, dstIA, 30, 50),  // 50ms
	}

	translator := NewTranslator(&mockPool{paths: paths}, srcIA, nil, "", nil)

	// No policy -> first valid path
	selected := translator.selectPathWithPolicy(paths, srcIA, dstIA)
	if selected.Path.Metadata().Latency[0] != 100*time.Millisecond {
		t.Fatalf("expected first path (100ms), got %v", selected.Path.Metadata().Latency[0])
	}

	// Load a policy that prefers low latency
	policyJSON := `{
		"matchers": [
			{"source": "1-ff00:0:110", "policy": "low_latency"}
		],
		"policies": {
			"low_latency": {
				"ordering": ["meta_latency_asc"]
			}
		}
	}`

	pf, err := pathpolicy.ParsePolicyFile([]byte(policyJSON))
	if err != nil {
		t.Fatalf("failed to parse policy: %v", err)
	}

	engine, err := pathpolicy.NewEngine(pf)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	translator.SetPolicyEngine(engine)

	// Now select path with policy -> should pick the 10ms path
	selectedWithPolicy := translator.selectPathWithPolicy(paths, srcIA, dstIA)
	if selectedWithPolicy.Path.Metadata().Latency[0] != 10*time.Millisecond {
		t.Fatalf("expected low latency path (10ms), got %v", selectedWithPolicy.Path.Metadata().Latency[0])
	}
}
