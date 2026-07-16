package device

import (
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

func mustIA(t *testing.T, isd int, asn uint64) addr.IA {
	t.Helper()
	return addr.IA(addr.MustIAFrom(addr.ISD(isd), addr.AS(asn)))
}

func TestPendingSCIONQueue_TTLExpiry(t *testing.T) {
	src := mustIA(t, 71, 2)
	dst := mustIA(t, 64, 2)

	q := NewPendingSCIONQueue(64, 10*time.Millisecond)

	pkt := []byte{0x60, 0x00, 0x00, 0x00}
	q.Enqueue(src, dst, pkt, true, 35000, 0)

	valid := q.Pop(src, dst)
	if len(valid) != 1 {
		t.Fatalf("expected 1 packet before expiry, got %d", len(valid))
	}

	time.Sleep(20 * time.Millisecond)

	valid = q.Pop(src, dst)
	if len(valid) != 0 {
		t.Fatalf("expected 0 packets after TTL expiry, got %d", len(valid))
	}
}

func TestPendingSCIONQueue_MaxPerKey(t *testing.T) {
	src := mustIA(t, 71, 2)
	dst := mustIA(t, 64, 2)

	q := NewPendingSCIONQueue(3, time.Minute)

	for i := 0; i < 5; i++ {
		pkt := []byte{byte(i)}
		q.Enqueue(src, dst, pkt, true, 35000, 0)
	}

	valid := q.Pop(src, dst)
	if len(valid) != 3 {
		t.Fatalf("expected 3 packets (maxPerKey), got %d", len(valid))
	}
}

func TestPendingSCIONQueue_CopiesPacket(t *testing.T) {
	src := mustIA(t, 71, 2)
	dst := mustIA(t, 64, 2)

	q := NewPendingSCIONQueue(64, time.Minute)

	pkt := []byte{0x60, 0x00, 0x00, 0x00}
	q.Enqueue(src, dst, pkt, true, 35000, 0)

	pkt[0] = 0x45

	valid := q.Pop(src, dst)
	if len(valid) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(valid))
	}
	if valid[0].packet[0] != 0x60 {
		t.Fatalf("packet should be copied, got first byte 0x%02x", valid[0].packet[0])
	}
}

func TestPendingSCIONQueue_DifferentKeys(t *testing.T) {
	src1 := mustIA(t, 71, 2)
	dst1 := mustIA(t, 64, 2)
	src2 := mustIA(t, 71, 3)
	dst2 := mustIA(t, 64, 3)

	q := NewPendingSCIONQueue(64, time.Minute)

	q.Enqueue(src1, dst1, []byte{1}, true, 35000, 0)
	q.Enqueue(src2, dst2, []byte{2}, true, 35000, 0)

	valid1 := q.Pop(src1, dst1)
	valid2 := q.Pop(src2, dst2)

	if len(valid1) != 1 {
		t.Fatalf("expected 1 packet for key1, got %d", len(valid1))
	}
	if len(valid2) != 1 {
		t.Fatalf("expected 1 packet for key2, got %d", len(valid2))
	}
}
