package flow

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParseIPv6ICMPv6Echo(t *testing.T) {
	pkt := make([]byte, 48)
	pkt[0] = 0x60
	// PayloadLength = 8 (ICMP header + identifier/sequence)
	binary.BigEndian.PutUint16(pkt[4:6], 8)
	pkt[6] = ProtocolICMPv6
	copy(pkt[8:24], netip.MustParseAddr("fd42::70").AsSlice())
	copy(pkt[24:40], netip.MustParseAddr("fc00::1").AsSlice())
	pkt[40] = 128 // Echo Request
	pkt[41] = 0
	// Checksum placeholder
	binary.BigEndian.PutUint16(pkt[44:46], 1234) // Identifier
	binary.BigEndian.PutUint16(pkt[46:48], 7)    // Sequence
	md, err := ParsePacketMetadata(pkt)
	if err != nil {
		t.Fatalf("parse err: %v", err)
	}
	if md.Protocol != ProtocolICMPv6 {
		t.Fatalf("expected ICMPv6, got %d", md.Protocol)
	}
	if md.Source.Port != 1234 || md.Destination.Port != 1234 {
		t.Fatalf("expected identifier 1234 both, got %d %d", md.Source.Port, md.Destination.Port)
	}
	// Reply should have same key (canonical)
	pkt2 := make([]byte, 48)
	copy(pkt2, pkt)
	// Swap src/dst for reply
	copy(pkt2[8:24], netip.MustParseAddr("fc00::1").AsSlice())
	copy(pkt2[24:40], netip.MustParseAddr("fd42::70").AsSlice())
	// Keep same identifier
	md2, err := ParsePacketMetadata(pkt2)
	if err != nil {
		t.Fatalf("parse reply err: %v", err)
	}
	m := NewManager()
	md.TrafficClass = ClassMappedSCION
	snap1, _ := m.ObserveTx(md, 100, EgressSCION)
	md2.TrafficClass = ClassMappedSCION
	snap2, created := m.ObserveTx(md2, 100, EgressSCION)
	if created {
		t.Fatal("expected same flow for reply")
	}
	if snap1.ID != snap2.ID {
		t.Fatalf("expected same flow ID, got %d vs %d", snap1.ID, snap2.ID)
	}
}
