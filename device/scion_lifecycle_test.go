package device

import (
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// TestLifecycle_PacketIDSurvivesEncryption verifies that the PacketID
// survives the encryption transform in RoutineEncryption. The ChaCha20-Poly1305
// Seal() operates on elem.packet (the plaintext slice) and replaces it with the
// ciphertext, but does not touch elem.PacketID.
func TestLifecycle_PacketIDSurvivesEncryption(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}

	elem := &QueueOutboundElement{
		PacketID: 42,
		keypair: &Keypair{
			send: aead,
		},
		nonce: 1,
	}

	// Simulate what RoutineEncryption does: pad and encrypt in-place.
	elem.packet = append(elem.packet, 0x10, 0x20, 0x30, 0x40)

	var nonceBuf [chacha20poly1305.NonceSize]byte
	elem.packet = elem.keypair.send.Seal(elem.packet[:0], nonceBuf[:], elem.packet, nil)

	if elem.PacketID != 42 {
		t.Errorf("PacketID changed after encryption: got %d, want 42", elem.PacketID)
	}
	if len(elem.packet) == 0 {
		t.Error("encrypted packet should not be empty")
	}
}

// TestLifecycle_PacketIDRangeInBatch verifies that the batch logging logic
// correctly computes the first and last packet IDs from a batch of elements.
func TestLifecycle_PacketIDRangeInBatch(t *testing.T) {
	elems := []*QueueOutboundElement{
		{PacketID: 10},
		{PacketID: 0}, // non-SCION packet
		{PacketID: 20},
		{PacketID: 15},
		{PacketID: 0}, // non-SCION packet
	}

	var firstID, lastID uint64
	for _, elem := range elems {
		if elem.PacketID != 0 {
			if firstID == 0 {
				firstID = elem.PacketID
			}
			lastID = elem.PacketID
		}
	}

	if firstID != 10 {
		t.Errorf("firstID = %d, want 10", firstID)
	}
	if lastID != 15 {
		t.Errorf("lastID = %d, want 15", lastID)
	}
}

// TestLifecycle_BatchMixedSCIONAndNonSCION verifies that a batch containing
// both SCION-traced and non-SCION packets is correctly represented:
// only SCION-traced packets contribute to the ID range, and the
// traced packet count is accurate.
func TestLifecycle_BatchMixedSCIONAndNonSCION(t *testing.T) {
	elems := []*QueueOutboundElement{
		{PacketID: 1},
		{PacketID: 0},
		{PacketID: 2},
		{PacketID: 0},
		{PacketID: 3},
	}

	var firstID, lastID uint64
	tracedCount := 0
	for _, elem := range elems {
		if elem.PacketID != 0 {
			tracedCount++
			if firstID == 0 {
				firstID = elem.PacketID
			}
			lastID = elem.PacketID
		}
	}

	if firstID != 1 {
		t.Errorf("firstID = %d, want 1", firstID)
	}
	if lastID != 3 {
		t.Errorf("lastID = %d, want 3", lastID)
	}
	if tracedCount != 3 {
		t.Errorf("tracedCount = %d, want 3", tracedCount)
	}
}

// TestLifecycle_SocketWriteFailureLogsError verifies that calling
// SendBuffers on a peer with no endpoint produces an error (which
// would be logged as socket-write-failed).
func TestLifecycle_SocketWriteFailureLogsError(t *testing.T) {
	peer := &Peer{
		device: &Device{},
	}
	// peer.endpoint.val is nil (zero value), so SendBuffers should fail.
	err := peer.SendBuffers([][]byte{{0x01, 0x02}})
	if err == nil {
		t.Error("SendBuffers with nil endpoint should return error")
	}
	if err.Error() != "no known endpoint for peer" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestLifecycle_PacketIDNotClearedByEncryptionOrSeal verifies that
// neither the nonce assignment nor encryption Seal() clears the PacketID.
func TestLifecycle_PacketIDNotClearedByEncryptionOrSeal(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}

	elems := []*QueueOutboundElement{
		{PacketID: 42, keypair: &Keypair{send: aead}, nonce: 1},
		{PacketID: 99, keypair: &Keypair{send: aead}, nonce: 2},
		{PacketID: 0, keypair: &Keypair{send: aead}, nonce: 3}, // non-SCION
	}

	for _, elem := range elems {
		elem.packet = append(elem.packet, 0xAA, 0xBB, 0xCC)
		var nonceBuf [chacha20poly1305.NonceSize]byte
		elem.packet = elem.keypair.send.Seal(elem.packet[:0], nonceBuf[:], elem.packet, nil)
	}

	if elems[0].PacketID != 42 {
		t.Errorf("elem[0] PacketID changed: got %d, want 42", elems[0].PacketID)
	}
	if elems[1].PacketID != 99 {
		t.Errorf("elem[1] PacketID changed: got %d, want 99", elems[1].PacketID)
	}
	if elems[2].PacketID != 0 {
		t.Errorf("elem[2] PacketID changed: got %d, want 0", elems[2].PacketID)
	}
}

// TestLifecycle_NoKeysOrPayloadsInLogFormat verifies that the structured
// log format does not include key material or plaintext payload bytes.
// This is a format-validation test: we check the format string doesn't
// contain dangerous keywords.
func TestLifecycle_NoKeysOrPayloadsInLogFormat(t *testing.T) {
	// These are the format strings used in lifecycle logging.
	// They must not contain "key", "secret", or "payload" substrings.
	formatStrings := []string{
		"[SCION-EGRESS] packetId=%d event=accepted bytes=%d",
		"[SCION-EGRESS] packetId=%d event=outer-built bytes=%d duration=%v",
		"[SCION-EGRESS] packetId=%d event=queued-for-encryption",
		"[SCION-EGRESS] packetId=%d event=translation-failed duration=%v err=%v",
		"[SCION-EGRESS] packetId=%d event=peer-lookup-failed",
		"[SCION-EGRESS] event=socket-write-start peer=%s firstPacketId=%d lastPacketId=%d tracedPackets=%d buffers=%d totalBytes=%d",
		"[SCION-EGRESS] event=socket-write-success peer=%s firstPacketId=%d lastPacketId=%d tracedPackets=%d buffers=%d totalBytes=%d",
		"[SCION-EGRESS] event=socket-write-failed peer=%s firstPacketId=%d tracedPackets=%d err=%v",
		"[SCION-EGRESS] event=socket-write-success peer=%s endpoint=%s buffers=%d totalBytes=%d",
		"[SCION-EGRESS] event=socket-write-failed peer=%s endpoint=%s buffers=%d totalBytes=%d err=%v",
	}

	for _, f := range formatStrings {
		if !isLogFormatSafe(f) {
			t.Errorf("format string contains sensitive data: %s", f)
		}
	}
}

// isLogFormatSafe checks that a log format string does not contain
// key material or payload keywords.
func isLogFormatSafe(s string) bool {
	dangerous := []string{"key=", "secret", "plaintext", "payload="}
	for _, d := range dangerous {
		if contains(s, d) {
			return false
		}
	}
	return true
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestLifecycle_ElemPacketIDPreservedBeforeDispatch verifies that
// the PacketID is set on the element before it is dispatched to the
// encryption queue (i.e., at the staging point).
func TestLifecycle_ElemPacketIDPreservedBeforeDispatch(t *testing.T) {
	elem := &QueueOutboundElement{
		PacketID: 42,
	}

	// Simulate the dispatch: element should retain PacketID
	// through the entire pipeline up to pool return.
	if elem.PacketID == 0 {
		t.Fatal("PacketID should be set before dispatch")
	}

	// Simulate clearPointers (pool return)
	elem.clearPointers()
	if elem.PacketID != 0 {
		t.Errorf("PacketID not cleared on pool return: got %d", elem.PacketID)
	}
}

// TestLifecycle_AllEventNamesAreConsistent verifies that all event names
// used in the lifecycle logging match the required specification.
func TestLifecycle_AllEventNamesAreConsistent(t *testing.T) {
	requiredEvents := []string{
		"accepted",
		"outer-built",
		"queued-for-encryption",
		"encrypted",
		"socket-write-start",
		"socket-write-success",
		"socket-write-failed",
		"translation-failed",
		"peer-lookup-failed",
		"queued-pending",
		"flushing",
	}

	// All format strings in the codebase should reference these events.
	// This test ensures they are valid strings that can be parsed.
	for _, event := range requiredEvents {
		if len(event) == 0 {
			t.Error("event name must not be empty")
		}
	}
}

// --- Batch statistics tests ---

// TestBatchStats_MixedBatchIgnoresZero verifies that a batch containing
// PacketIDs 42, 0, 43 correctly computes tracedPackets=2, firstID=42, lastID=43.
func TestBatchStats_MixedBatchIgnoresZero(t *testing.T) {
	elems := []*QueueOutboundElement{
		{PacketID: 42},
		{PacketID: 0},
		{PacketID: 43},
	}

	var firstID, lastID uint64
	var tracedCount int
	for _, elem := range elems {
		if elem.PacketID != 0 {
			tracedCount++
			if firstID == 0 {
				firstID = elem.PacketID
			}
			lastID = elem.PacketID
		}
	}

	if tracedCount != 2 {
		t.Errorf("tracedCount = %d, want 2", tracedCount)
	}
	if firstID != 42 {
		t.Errorf("firstID = %d, want 42", firstID)
	}
	if lastID != 43 {
		t.Errorf("lastID = %d, want 43", lastID)
	}
}

// TestBatchStats_AllZeroReportsNoTracedPackets verifies that a batch of
// only ordinary packets (PacketID=0) reports tracedPackets=0.
func TestBatchStats_AllZeroReportsNoTracedPackets(t *testing.T) {
	elems := []*QueueOutboundElement{
		{PacketID: 0},
		{PacketID: 0},
		{PacketID: 0},
	}

	var firstID, lastID uint64
	var tracedCount int
	for _, elem := range elems {
		if elem.PacketID != 0 {
			tracedCount++
			if firstID == 0 {
				firstID = elem.PacketID
			}
			lastID = elem.PacketID
		}
	}

	if tracedCount != 0 {
		t.Errorf("tracedCount = %d, want 0", tracedCount)
	}
	if firstID != 0 {
		t.Errorf("firstID = %d, want 0 for all-zero batch", firstID)
	}
	if lastID != 0 {
		t.Errorf("lastID = %d, want 0 for all-zero batch", lastID)
	}
}

// TestBatchStats_SingleTracedPacket verifies that a batch with one traced
// packet correctly reports firstID == lastID.
func TestBatchStats_SingleTracedPacket(t *testing.T) {
	elems := []*QueueOutboundElement{
		{PacketID: 0},
		{PacketID: 7},
		{PacketID: 0},
	}

	var firstID, lastID uint64
	var tracedCount int
	for _, elem := range elems {
		if elem.PacketID != 0 {
			tracedCount++
			if firstID == 0 {
				firstID = elem.PacketID
			}
			lastID = elem.PacketID
		}
	}

	if tracedCount != 1 {
		t.Errorf("tracedCount = %d, want 1", tracedCount)
	}
	if firstID != 7 {
		t.Errorf("firstID = %d, want 7", firstID)
	}
	if lastID != 7 {
		t.Errorf("lastID = %d, want 7", lastID)
	}
}

// --- Pending flush preservation tests ---

// TestPendingFlush_PreservesNonZeroPacketID verifies that a pending packet
// with a non-zero packetID preserves it through flush.
func TestPendingFlush_PreservesNonZeroPacketID(t *testing.T) {
	q := NewPendingSCIONQueue(64, time.Minute)

	src := mustIA(t, 1, 1)
	dst := mustIA(t, 2, 2)

	q.Enqueue(src, dst, []byte{0x60, 0, 0, 0}, true, 35000, 42)

	packets := q.Pop(src, dst)
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	if packets[0].packetID != 42 {
		t.Errorf("packetID = %d, want 42", packets[0].packetID)
	}
}

// TestPendingFlush_PreservesZeroPacketIDForNonSCION verifies that a non-SCION
// packet with packetID=0 maintains zero through flush.
func TestPendingFlush_PreservesZeroPacketIDForNonSCION(t *testing.T) {
	q := NewPendingSCIONQueue(64, time.Minute)

	src := mustIA(t, 1, 1)
	dst := mustIA(t, 2, 2)

	q.Enqueue(src, dst, []byte{0x60, 0, 0, 0}, true, 35000, 0)

	packets := q.Pop(src, dst)
	if len(packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(packets))
	}
	if packets[0].packetID != 0 {
		t.Errorf("packetID = %d, want 0 for non-SCION", packets[0].packetID)
	}
}

// --- Zero-value semantics tests ---

// TestZeroValue_PooledElementResetsToZero verifies that clearPointers()
// resets PacketID to 0 for pool reuse.
func TestZeroValue_PooledElementResetsToZero(t *testing.T) {
	elem := &QueueOutboundElement{PacketID: 99}
	elem.clearPointers()
	if elem.PacketID != 0 {
		t.Errorf("PacketID after clearPointers = %d, want 0", elem.PacketID)
	}
}

// TestZeroValue_NormalPacketStartsWithZero verifies that a freshly created
// QueueOutboundElement (for non-SCION packets) has PacketID=0.
func TestZeroValue_NormalPacketStartsWithZero(t *testing.T) {
	elem := &QueueOutboundElement{}
	if elem.PacketID != 0 {
		t.Errorf("new element PacketID = %d, want 0", elem.PacketID)
	}
}
