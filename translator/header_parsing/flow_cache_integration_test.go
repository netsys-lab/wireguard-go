package header_parsing

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	pathpool "golang.zx2c4.com/wireguard/translator/pathpool"
)

// countingMockPool counts how many times Get() is invoked on the PathPool.
type countingMockPool struct {
	getCalled atomic.Int64
	paths     []pathpool.CachedPath
}

func (m *countingMockPool) Get(ctx context.Context, srcIA, dstIA addr.IA) ([]pathpool.CachedPath, error) {
	m.getCalled.Add(1)
	return m.paths, nil
}

func TestFlowPathCache_EgressIntegration(t *testing.T) {
	srcIA := addr.MustIAFrom(1, 64512)
	dstIA := addr.MustIAFrom(2, 64534)

	mockSnetPath := path.Path{
		Src: srcIA,
		Dst: dstIA,
		NextHop: &net.UDPAddr{
			IP:   net.ParseIP("192.0.2.1"),
			Port: 30041,
		},
		Meta: snet.PathMetadata{
			Expiry: time.Now().Add(10 * time.Minute),
		},
	}

	pool := &countingMockPool{
		paths: []pathpool.CachedPath{
			{
				Src:         srcIA,
				Dst:         dstIA,
				Path:        mockSnetPath,
				NextHop:     mockSnetPath.NextHop,
				Fingerprint: "test-fp-1",
				Expiry:      time.Now().Add(10 * time.Minute),
			},
		},
	}

	tr := NewTranslator(pool, srcIA, &net.UDPAddr{IP: net.ParseIP("127.0.0.9"), Port: 31002}, "", nil)
	defer tr.Close()

	// Build a valid SCION-mapped IPv6 TCP SYN packet
	// Dst IP: mapped SCION IP for ISD 2, AS 64534, host 192.0.2.10
	dstIP := net.ParseIP("fc00:2:fbfe:0:0:0:c000:20a") // mapped SCION IP
	srcIP := net.ParseIP("fd42:42:42::1")

	// Helper to build a valid IPv6+TCP packet
	buildPacket := func(srcPort, dstPort uint16) []byte {
		buf := gopacket.NewSerializeBuffer()
		ip := &layers.IPv6{
			Version:    6,
			SrcIP:      srcIP,
			DstIP:      dstIP,
			NextHeader: layers.IPProtocolTCP,
			HopLimit:   64,
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			SYN:     true,
			Seq:     100,
			Window:  65535,
		}
		tcp.SetNetworkLayerForChecksum(ip)
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ip, tcp); err != nil {
			t.Fatalf("failed to serialize test packet: %v", err)
		}
		return buf.Bytes()
	}

	pkt1 := buildPacket(45678, 80)

	// --- 1. First packet of Flow A: Cache Miss -> Must query pool.Get() ---
	out1, nextHop1, err := tr.TranslateEgress(pkt1, net.ParseIP("10.0.0.1"), 30041, nil)
	if err != nil {
		t.Fatalf("first packet failed: %v", err)
	}
	if len(out1) == 0 || nextHop1 == nil {
		t.Fatalf("expected valid scion output and nextHop")
	}
	if pool.getCalled.Load() != 1 {
		t.Fatalf("expected pool.Get to be called exactly 1 time, got %d", pool.getCalled.Load())
	}
	if tr.FlowCache().Len() != 1 {
		t.Fatalf("expected flowCache to have 1 entry, got %d", tr.FlowCache().Len())
	}

	// --- 2. Subsequent packets (100 packets) of Flow A: Must HIT cache -> 0 pool.Get() calls! ---
	for i := 0; i < 100; i++ {
		out, nextHop, err := tr.TranslateEgress(pkt1, net.ParseIP("10.0.0.1"), 30041, nil)
		if err != nil {
			t.Fatalf("subsequent packet %d failed: %v", i, err)
		}
		if len(out) == 0 || nextHop == nil {
			t.Fatalf("subsequent packet %d returned empty output", i)
		}
	}

	// pool.Get must STILL be 1! (100% cache hits!)
	if pool.getCalled.Load() != 1 {
		t.Fatalf("expected pool.Get to STILL be 1 after 100 packets, got %d (cache was bypassed!)", pool.getCalled.Load())
	}

	// --- 3. Packet from Flow B (different port): Cache Miss -> Exactly 1 more pool.Get() call ---
	pkt2 := buildPacket(45679, 80)
	_, _, err = tr.TranslateEgress(pkt2, net.ParseIP("10.0.0.1"), 30041, nil)
	if err != nil {
		t.Fatalf("flow B packet failed: %v", err)
	}
	if pool.getCalled.Load() != 2 {
		t.Fatalf("expected pool.Get to be called 2 times now, got %d", pool.getCalled.Load())
	}
	if tr.FlowCache().Len() != 2 {
		t.Fatalf("expected flowCache to have 2 entries, got %d", tr.FlowCache().Len())
	}

	// --- 4. SCMP Failover: Simulate SCMP Error packet for Flow A ---
	// Extract wire tuple of Flow A
	flowKeyA, _ := ExtractFlowKey(pkt1)
	entryA, hit, _ := tr.FlowCache().Get(flowKeyA)
	if !hit {
		t.Fatalf("expected flow A to be present in cache")
	}

	// Invalidate via wire tuple (as received in SCMP error)
	scmpQuote := &entryA.WireTuple
	invalidated := tr.InvalidateFlowPathBySCIONTuple(scmpQuote)
	if invalidated != 1 {
		t.Fatalf("expected 1 flow to be invalidated by SCMP quote, got %d", invalidated)
	}

	// Verify Flow A is evicted, while Flow B remains
	if _, hit, _ := tr.FlowCache().Get(flowKeyA); hit {
		t.Fatalf("expected flow A to be evicted from cache after SCMP error")
	}
	if tr.FlowCache().Len() != 1 {
		t.Fatalf("expected flowCache to have 1 entry (Flow B) remaining, got %d", tr.FlowCache().Len())
	}

	// --- 5. Flow A next packet: Must query pool.Get() again (re-routed / failover) ---
	_, _, err = tr.TranslateEgress(pkt1, net.ParseIP("10.0.0.1"), 30041, nil)
	if err != nil {
		t.Fatalf("flow A re-query packet failed: %v", err)
	}
	if pool.getCalled.Load() != 3 {
		t.Fatalf("expected pool.Get to be called 3 times after SCMP failover re-query, got %d", pool.getCalled.Load())
	}
}
