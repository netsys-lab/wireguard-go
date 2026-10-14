package flow

import (
	"net/netip"
	"testing"
)

func TestParseIPv4TCP(t *testing.T) {
	packet := []byte{
		0x45, 0x00, 0x00, 0x18,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x02,
		0x0a, 0x00, 0x00, 0x03,
		0xc0, 0x00, 0x01, 0xbb,
	}

	meta, err := ParsePacketMetadata(packet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.IPVersion != 4 {
		t.Errorf("IPVersion: got %d, want 4", meta.IPVersion)
	}
	if meta.Protocol != ProtocolTCP {
		t.Errorf("Protocol: got %d, want %d", meta.Protocol, ProtocolTCP)
	}
	if meta.Source.Addr != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("Source.Addr: got %s, want 10.0.0.2", meta.Source.Addr)
	}
	if meta.Source.Port != 49152 {
		t.Errorf("Source.Port: got %d, want 49152", meta.Source.Port)
	}
	if meta.Destination.Addr != netip.MustParseAddr("10.0.0.3") {
		t.Errorf("Destination.Addr: got %s, want 10.0.0.3", meta.Destination.Addr)
	}
	if meta.Destination.Port != 443 {
		t.Errorf("Destination.Port: got %d, want 443", meta.Destination.Port)
	}
}

func TestParseIPv4UDP(t *testing.T) {
	packet := []byte{
		0x45, 0x00, 0x00, 0x18,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x02,
		0x0a, 0x00, 0x00, 0x03,
		0xc0, 0x00, 0x01, 0xbb,
	}

	meta, err := ParsePacketMetadata(packet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Protocol != ProtocolUDP {
		t.Errorf("Protocol: got %d, want %d", meta.Protocol, ProtocolUDP)
	}
}

func TestParseIPv4WithOptions(t *testing.T) {
	packet := []byte{
		0x46, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x02,
		0x0a, 0x00, 0x00, 0x03,
		0x01, 0x02, 0x03, 0x04,
		0xc0, 0x00, 0x01, 0xbb,
	}

	meta, err := ParsePacketMetadata(packet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.IPVersion != 4 {
		t.Errorf("IPVersion: got %d, want 4", meta.IPVersion)
	}
	if meta.Source.Port != 49152 {
		t.Errorf("Source.Port: got %d, want 49152", meta.Source.Port)
	}
	if meta.Destination.Port != 443 {
		t.Errorf("Destination.Port: got %d, want 443", meta.Destination.Port)
	}
}

func TestParseIPv4Truncated(t *testing.T) {
	packet := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06}

	_, err := ParsePacketMetadata(packet)
	if err == nil {
		t.Fatal("expected error for truncated packet, got nil")
	}
}

func TestParseIPv4Fragment(t *testing.T) {
	packet := []byte{
		0x45, 0x00, 0x00, 0x18,
		0x00, 0x00, 0x00, 0x01,
		0x40, 0x06, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x02,
		0x0a, 0x00, 0x00, 0x03,
		0xc0, 0x00, 0x01, 0xbb,
	}

	_, err := ParsePacketMetadata(packet)
	if err != ErrIPv4Fragment {
		t.Fatalf("expected ErrIPv4Fragment, got %v", err)
	}
}

func TestParseIPv6TCP(t *testing.T) {
	packet := []byte{
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x04, 0x06, 0x40,
		0xfd, 0x42, 0x00, 0x42, 0x00, 0x42, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xc0, 0x00, 0x01, 0xbb,
	}

	meta, err := ParsePacketMetadata(packet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.IPVersion != 6 {
		t.Errorf("IPVersion: got %d, want 6", meta.IPVersion)
	}
	if meta.Protocol != ProtocolTCP {
		t.Errorf("Protocol: got %d, want %d", meta.Protocol, ProtocolTCP)
	}
	if meta.Source.Addr != netip.MustParseAddr("fd42:42:42::70") {
		t.Errorf("Source.Addr: got %s, want fd42:42:42::70", meta.Source.Addr)
	}
	if meta.Source.Port != 49152 {
		t.Errorf("Source.Port: got %d, want 49152", meta.Source.Port)
	}
	if meta.Destination.Addr != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("Destination.Addr: got %s, want 2001:db8::1", meta.Destination.Addr)
	}
	if meta.Destination.Port != 443 {
		t.Errorf("Destination.Port: got %d, want 443", meta.Destination.Port)
	}
}

func TestParseIPv6UDP(t *testing.T) {
	packet := []byte{
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x04, 0x11, 0x40,
		0xfd, 0x42, 0x00, 0x42, 0x00, 0x42, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xc0, 0x00, 0x01, 0xbb,
	}

	meta, err := ParsePacketMetadata(packet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.Protocol != ProtocolUDP {
		t.Errorf("Protocol: got %d, want %d", meta.Protocol, ProtocolUDP)
	}
}

func TestParseIPv6Truncated(t *testing.T) {
	packet := make([]byte, 20)

	_, err := ParsePacketMetadata(packet)
	if err == nil {
		t.Fatal("expected error for truncated IPv6, got nil")
	}
}

func TestParseIPv6ExtensionHeader(t *testing.T) {
	packet := []byte{
		0x60, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x40,
		0xfd, 0x42, 0x00, 0x42, 0x00, 0x42, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	_, err := ParsePacketMetadata(packet)
	if err != ErrIPv6ExtensionHdr {
		t.Fatalf("expected ErrIPv6ExtensionHdr, got %v", err)
	}
}

func TestParseUnsupportedProtocol(t *testing.T) {
	packet := []byte{
		0x45, 0x00, 0x00, 0x18,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x01, 0x00, 0x00,
		0x0a, 0x00, 0x00, 0x02,
		0x0a, 0x00, 0x00, 0x03,
		0xc0, 0x00, 0x01, 0xbb,
	}

	_, err := ParsePacketMetadata(packet)
	if err != ErrUnsupportedProto {
		t.Fatalf("expected ErrUnsupportedProto, got %v", err)
	}
}

func TestParseUnknownIPVersion(t *testing.T) {
	packet := []byte{0x70, 0x00, 0x00, 0x00}

	_, err := ParsePacketMetadata(packet)
	if err == nil {
		t.Fatal("expected error for unknown IP version, got nil")
	}
}
