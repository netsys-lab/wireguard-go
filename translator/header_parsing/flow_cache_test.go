package header_parsing

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

func TestExtractFlowKey(t *testing.T) {
	t.Run("IPv6 TCP packet", func(t *testing.T) {
		pkt := make([]byte, 60)
		pkt[0] = 0x60 // IPv6
		pkt[6] = 6    // TCP

		src := netip.MustParseAddr("2001:db8::1").As16()
		dst := netip.MustParseAddr("fc00:1:2::3").As16()
		copy(pkt[8:24], src[:])
		copy(pkt[24:40], dst[:])

		binary.BigEndian.PutUint16(pkt[40:42], 54321) // srcPort
		binary.BigEndian.PutUint16(pkt[42:44], 443)   // dstPort

		key, ok := ExtractFlowKey(pkt)
		if !ok {
			t.Fatalf("expected ExtractFlowKey to succeed")
		}

		if key.SrcAddr != netip.MustParseAddr("2001:db8::1") {
			t.Errorf("unexpected srcAddr: %v", key.SrcAddr)
		}
		if key.DstAddr != netip.MustParseAddr("fc00:1:2::3") {
			t.Errorf("unexpected dstAddr: %v", key.DstAddr)
		}
		if key.SrcPort != 54321 || key.DstPort != 443 {
			t.Errorf("unexpected ports: src=%d, dst=%d", key.SrcPort, key.DstPort)
		}
		if key.Proto != 6 {
			t.Errorf("unexpected proto: %d", key.Proto)
		}
	})

	t.Run("IPv6 UDP packet", func(t *testing.T) {
		pkt := make([]byte, 48)
		pkt[0] = 0x60 // IPv6
		pkt[6] = 17   // UDP

		src := netip.MustParseAddr("fd42::1").As16()
		dst := netip.MustParseAddr("fc00:2:3::4").As16()
		copy(pkt[8:24], src[:])
		copy(pkt[24:40], dst[:])

		binary.BigEndian.PutUint16(pkt[40:42], 1234)
		binary.BigEndian.PutUint16(pkt[42:44], 5678)

		key, ok := ExtractFlowKey(pkt)
		if !ok {
			t.Fatalf("expected ExtractFlowKey to succeed")
		}
		if key.SrcPort != 1234 || key.DstPort != 5678 || key.Proto != 17 {
			t.Errorf("unexpected key fields: %+v", key)
		}
	})

	t.Run("IPv6 ICMPv6 Echo Request", func(t *testing.T) {
		pkt := make([]byte, 48)
		pkt[0] = 0x60 // IPv6
		pkt[6] = 58   // ICMPv6

		src := netip.MustParseAddr("fd42::1").As16()
		dst := netip.MustParseAddr("fc00:2:3::4").As16()
		copy(pkt[8:24], src[:])
		copy(pkt[24:40], dst[:])

		pkt[40] = 128                               // Echo Request
		binary.BigEndian.PutUint16(pkt[44:46], 9999) // Ident

		key, ok := ExtractFlowKey(pkt)
		if !ok {
			t.Fatalf("expected ExtractFlowKey to succeed for ICMPv6 echo")
		}
		if key.SrcPort != 9999 || key.DstPort != 9999 || key.Proto != 58 {
			t.Errorf("unexpected ICMPv6 key: %+v", key)
		}
	})

	t.Run("Truncated or invalid packets", func(t *testing.T) {
		short := make([]byte, 30)
		short[0] = 0x60
		if _, ok := ExtractFlowKey(short); ok {
			t.Errorf("expected failure for short packet")
		}

		ipv4 := make([]byte, 50)
		ipv4[0] = 0x45
		if _, ok := ExtractFlowKey(ipv4); ok {
			t.Errorf("expected failure for IPv4 packet")
		}
	})
}

func TestFlowPathCache_PutAndGet(t *testing.T) {
	cache := NewFlowPathCache(nil)
	defer cache.Close()

	key := FlowKey{
		SrcAddr: netip.MustParseAddr("fd42::1"),
		DstAddr: netip.MustParseAddr("fc00:1:2::3"),
		SrcPort: 12345,
		DstPort: 80,
		Proto:   6,
	}

	srcIA := addr.MustIAFrom(1, 64512)
	dstIA := addr.MustIAFrom(2, 64534)
	mockPath := path.Path{
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

	// 1. Initial miss
	if _, hit, _ := cache.Get(key); hit {
		t.Fatalf("expected initial cache miss")
	}

	// 2. Put
	wireTuple := SCIONTuple{
		Protocol: 6,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		SrcHost:  netip.MustParseAddr("192.0.2.100"),
		DstHost:  netip.MustParseAddr("192.0.2.200"),
		SrcPort:  12345,
		DstPort:  80,
	}
	cache.Put(key, mockPath, srcIA, dstIA, wireTuple)

	// 3. Cache hit
	entry, hit, needsRefresh := cache.Get(key)
	if !hit {
		t.Fatalf("expected cache hit after Put")
	}
	if needsRefresh {
		t.Errorf("expected needsRefresh=false for path expiring in 10 minutes")
	}
	if entry.SrcIA != srcIA || entry.DstIA != dstIA {
		t.Errorf("mismatched IA: src=%s dst=%s", entry.SrcIA, entry.DstIA)
	}
	if entry.NextHop.String() != "192.0.2.1:30041" {
		t.Errorf("unexpected NextHop: %v", entry.NextHop)
	}
}

func TestFlowPathCache_HardExpiry(t *testing.T) {
	cache := NewFlowPathCache(nil)
	defer cache.Close()

	key := FlowKey{
		SrcAddr: netip.MustParseAddr("fd42::1"),
		DstAddr: netip.MustParseAddr("fc00:1:2::3"),
		SrcPort: 12345,
		DstPort: 80,
		Proto:   6,
	}

	// Create path with already expired time
	srcIA := addr.MustIAFrom(1, 64512)
	dstIA := addr.MustIAFrom(2, 64534)
	mockPath := path.Path{
		Src: srcIA,
		Dst: dstIA,
		Meta: snet.PathMetadata{
			Expiry: time.Now().Add(-1 * time.Second), // Expired!
		},
	}

	cache.Put(key, mockPath, srcIA, dstIA, SCIONTuple{})

	if _, hit, _ := cache.Get(key); hit {
		t.Fatalf("expected cache miss for hard-expired path")
	}
	if cache.Len() != 0 {
		t.Fatalf("expected expired entry to be evicted from cache, len=%d", cache.Len())
	}
}

func TestFlowPathCache_SoftExpiry(t *testing.T) {
	cache := NewFlowPathCache(nil)
	defer cache.Close()

	cache.SetSoftExpiryWindow(30 * time.Second)

	key := FlowKey{
		SrcAddr: netip.MustParseAddr("fd42::1"),
		DstAddr: netip.MustParseAddr("fc00:1:2::3"),
		SrcPort: 12345,
		DstPort: 80,
		Proto:   6,
	}

	// Path expires in 15 seconds (within the 30-second soft-expiry window)
	srcIA := addr.MustIAFrom(1, 64512)
	dstIA := addr.MustIAFrom(2, 64534)
	mockPath := path.Path{
		Src: srcIA,
		Dst: dstIA,
		Meta: snet.PathMetadata{
			Expiry: time.Now().Add(15 * time.Second),
		},
	}

	cache.Put(key, mockPath, srcIA, dstIA, SCIONTuple{})

	// Should report hit=true AND needsRefresh=true so caller can query fresh path while continuing to use existing path
	entry, hit, needsRefresh := cache.Get(key)
	if !hit {
		t.Fatalf("expected hit=true during soft-expiry window for fallback")
	}
	if !needsRefresh {
		t.Fatalf("expected needsRefresh=true for path expiring in 15 seconds (<30s window)")
	}
	if entry == nil || entry.SrcIA != srcIA {
		t.Fatalf("expected valid entry returned during soft-expiry")
	}
}

func TestFlowPathCache_SCMPInvalidation(t *testing.T) {
	cache := NewFlowPathCache(nil)
	defer cache.Close()

	key := FlowKey{
		SrcAddr: netip.MustParseAddr("fd42::1"),
		DstAddr: netip.MustParseAddr("fc00:1:2::3"),
		SrcPort: 50000,
		DstPort: 443,
		Proto:   6,
	}

	srcIA := addr.MustIAFrom(1, 64512)
	dstIA := addr.MustIAFrom(2, 64534)
	mockPath := path.Path{
		Src: srcIA,
		Dst: dstIA,
		Meta: snet.PathMetadata{
			Expiry: time.Now().Add(10 * time.Minute),
		},
	}

	wireTuple := SCIONTuple{
		Protocol: 6,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		SrcHost:  netip.MustParseAddr("10.0.0.1"),
		DstHost:  netip.MustParseAddr("10.0.0.2"),
		SrcPort:  50000,
		DstPort:  443,
	}
	cache.Put(key, mockPath, srcIA, dstIA, wireTuple)

	// Verify hit before SCMP
	if _, hit, _ := cache.Get(key); !hit {
		t.Fatalf("expected cache hit")
	}

	// Simulate inbound SCMP Error with quoted tuple
	scmpQuoted := &SCIONTuple{
		Protocol: 6,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		SrcHost:  netip.MustParseAddr("10.0.0.1"),
		DstHost:  netip.MustParseAddr("10.0.0.2"),
		SrcPort:  50000,
		DstPort:  443,
	}

	invalidated := cache.InvalidateBySCIONTuple(scmpQuoted)
	if invalidated != 1 {
		t.Fatalf("expected 1 invalidated flow, got %d", invalidated)
	}

	// Verify cache miss after SCMP
	if _, hit, _ := cache.Get(key); hit {
		t.Fatalf("expected cache miss after SCMP invalidation")
	}
}

func TestFlowPathCache_Concurrency(t *testing.T) {
	cache := NewFlowPathCache(nil)
	defer cache.Close()

	var wg sync.WaitGroup
	workers := 20
	iterations := 500

	srcIA := addr.MustIAFrom(1, 64512)
	dstIA := addr.MustIAFrom(2, 64534)
	mockPath := path.Path{
		Src: srcIA,
		Dst: dstIA,
		Meta: snet.PathMetadata{
			Expiry: time.Now().Add(10 * time.Minute),
		},
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			key := FlowKey{
				SrcAddr: netip.MustParseAddr("fd42::1"),
				DstAddr: netip.MustParseAddr("fc00:1:2::3"),
				SrcPort: uint16(1000 + workerID),
				DstPort: 80,
				Proto:   6,
			}

			for i := 0; i < iterations; i++ {
				cache.Put(key, mockPath, srcIA, dstIA, SCIONTuple{})
				if _, hit, _ := cache.Get(key); !hit {
					t.Errorf("worker %d: expected hit on iteration %d", workerID, i)
				}
				if i%50 == 0 {
					cache.Invalidate(key)
				}
			}
		}(w)
	}

	wg.Wait()
}
