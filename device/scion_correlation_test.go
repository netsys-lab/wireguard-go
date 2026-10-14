package device

import (
	"sync"
	"testing"
	"time"
)

// --- Packet ID tests ---

func TestPacketID_FirstIDIsOne(t *testing.T) {
	device := &Device{}

	id1 := device.NextPacketID()
	if id1 != 1 {
		t.Errorf("first packet ID = %d, want 1", id1)
	}
}

func TestPacketID_SecondIDIsTwo(t *testing.T) {
	device := &Device{}

	id1 := device.NextPacketID()
	id2 := device.NextPacketID()

	if id1 != 1 {
		t.Errorf("first packet ID = %d, want 1", id1)
	}
	if id2 != 2 {
		t.Errorf("second packet ID = %d, want 2", id2)
	}
}

func TestPacketID_NextPacketIDReturnsMonotonicValues(t *testing.T) {
	// Create a minimal Device to test the counter.
	// We only need the packetIDCounter field, so we construct a bare Device.
	device := &Device{}

	id1 := device.NextPacketID()
	id2 := device.NextPacketID()
	id3 := device.NextPacketID()

	if id1 != 1 {
		t.Errorf("first packet ID = %d, want 1", id1)
	}
	if id2 != 2 {
		t.Errorf("second packet ID = %d, want 2", id2)
	}
	if id3 != 3 {
		t.Errorf("third packet ID = %d, want 3", id3)
	}
}

func TestPacketID_ConcurrentNextPacketID(t *testing.T) {
	device := &Device{}

	const goroutines = 100
	const perGoroutine = 100

	ids := make([]uint64, goroutines*perGoroutine)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(base int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				ids[base+i] = device.NextPacketID()
			}
		}(g * perGoroutine)
	}
	wg.Wait()

	// All IDs must be unique.
	seen := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate packet ID: %d", id)
		}
		seen[id] = true
	}

	if len(seen) != goroutines*perGoroutine {
		t.Fatalf("expected %d unique IDs, got %d", goroutines*perGoroutine, len(seen))
	}
}

func TestOutboundElement_PacketIDClearedOnReturn(t *testing.T) {
	elem := &QueueOutboundElement{
		PacketID: 42,
	}

	elem.clearPointers()

	if elem.PacketID != 0 {
		t.Errorf("PacketID should be 0 after clearPointers, got %d", elem.PacketID)
	}
}

func TestOutboundElement_PacketIDZeroByDefault(t *testing.T) {
	elem := &QueueOutboundElement{}

	if elem.PacketID != 0 {
		t.Errorf("new QueueOutboundElement PacketID should be 0, got %d", elem.PacketID)
	}
}

// --- PendingSCIONPacket correlation tests ---

func TestPendingSCIONPacket_PreservesPacketID(t *testing.T) {
	src := mustIA(t, 71, 2)
	dst := mustIA(t, 64, 2)

	q := NewPendingSCIONQueue(64, time.Minute)

	pkt := []byte{0x60, 0x00, 0x00, 0x00}
	q.Enqueue(src, dst, pkt, true, 35000, 42)

	valid := q.Pop(src, dst)
	if len(valid) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(valid))
	}
	if valid[0].packetID != 42 {
		t.Errorf("expected packetID=42, got %d", valid[0].packetID)
	}
}

func TestPendingSCIONPacket_DifferentIDsPreserved(t *testing.T) {
	src := mustIA(t, 71, 2)
	dst := mustIA(t, 64, 2)

	q := NewPendingSCIONQueue(64, time.Minute)

	q.Enqueue(src, dst, []byte{1}, true, 35000, 100)
	q.Enqueue(src, dst, []byte{2}, true, 35000, 200)
	q.Enqueue(src, dst, []byte{3}, true, 35000, 300)

	valid := q.Pop(src, dst)
	if len(valid) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(valid))
	}
	expected := []uint64{100, 200, 300}
	for i, p := range valid {
		if p.packetID != expected[i] {
			t.Errorf("packet %d: expected packetID=%d, got %d", i, expected[i], p.packetID)
		}
	}
}

func TestPendingSCIONPacket_ZeroIDForNonSCION(t *testing.T) {
	src := mustIA(t, 71, 2)
	dst := mustIA(t, 64, 2)

	q := NewPendingSCIONQueue(64, time.Minute)

	// Non-SCION packets use packetID=0
	q.Enqueue(src, dst, []byte{1}, true, 35000, 0)

	valid := q.Pop(src, dst)
	if len(valid) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(valid))
	}
	if valid[0].packetID != 0 {
		t.Errorf("expected packetID=0 for non-SCION, got %d", valid[0].packetID)
	}
}
