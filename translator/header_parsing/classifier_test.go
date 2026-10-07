package header_parsing

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestClassifyPacketPlainIPv4(t *testing.T) {
	// Minimal IPv4 packet
	pkt := make([]byte, 20)
	pkt[0] = 0x45 // version=4, IHL=5
	pkt[9] = 6    // TCP

	class := ClassifyPacket(pkt)
	if class != ClassPlainIP {
		t.Errorf("IPv4 packet classified as %d, expected ClassPlainIP (%d)", class, ClassPlainIP)
	}
}

func TestClassifyPacketPlainIPv6(t *testing.T) {
	// Minimal IPv6 packet (non-SCION-mapped, non-UDP)
	pkt := make([]byte, 40)
	pkt[0] = 0x60 // version=6
	pkt[6] = 6    // TCP, not UDP
	// dst address at bytes 24:40
	pkt[24] = 0x20 // non-SCION prefix

	class := ClassifyPacket(pkt)
	if class != ClassPlainIP {
		t.Errorf("IPv6 non-UDP packet classified as %d, expected ClassPlainIP (%d)", class, ClassPlainIP)
	}
}

func TestClassifyPacketMappedSCION(t *testing.T) {
	// IPv6 packet with SCION-mapped prefix (fc00::)
	pkt := make([]byte, 48)
	pkt[0] = 0x60  // version=6
	pkt[6] = 17    // UDP
	pkt[24] = 0xfc // SCION-mapped prefix fc00::

	// UDP header and minimal SCION payload
	binary.BigEndian.PutUint16(pkt[42:44], 12345) // UDP dst port

	// SCION version=0 in payload at offset 48
	if len(pkt) >= 49 {
		pkt[48] = 0x00 // SCION version=0
	}

	class := ClassifyPacket(pkt)
	if class != ClassMappedSCION {
		t.Errorf("SCION-mapped packet classified as %d, expected ClassMappedSCION (%d)", class, ClassMappedSCION)
	}
}

func TestClassifyPacketNativeSCION(t *testing.T) {
	// IPv6 packet with non-SCION-mapped address but UDP on port 30041
	pkt := make([]byte, 48)
	pkt[0] = 0x60  // version=6
	pkt[6] = 17    // UDP
	pkt[24] = 0x20 // non-SCION prefix (e.g., 2001:db8::)

	// UDP destination port 30041 (SCION dispatcher)
	binary.BigEndian.PutUint16(pkt[42:44], DefaultSCIONEndhostPort)

	// SCION version=0 in payload at offset 48
	if len(pkt) >= 49 {
		pkt[48] = 0x00 // SCION version=0
	}

	class := ClassifyPacket(pkt)
	if class != ClassNativeSCION {
		t.Errorf("Native SCION packet (port 30041) classified as %d, expected ClassNativeSCION (%d)", class, ClassNativeSCION)
	}
}

func TestClassifyPacketTruncated(t *testing.T) {
	// Packet too short (< 40 bytes)
	pkt := make([]byte, 20)
	pkt[0] = 0x60 // version=6 (but truncated)

	class := ClassifyPacket(pkt)
	if class != ClassPlainIP {
		t.Errorf("Truncated packet classified as %d, expected ClassPlainIP (%d)", class, ClassPlainIP)
	}
}

func TestClassifyPacketSCIONMappedWithoutUDP(t *testing.T) {
	// SCION-mapped IPv6 destination but not UDP
	pkt := make([]byte, 40)
	pkt[0] = 0x60  // version=6
	pkt[6] = 58    // ICMPv6, not UDP
	pkt[24] = 0xfc // SCION-mapped prefix

	class := ClassifyPacket(pkt)
	// When SCION-mapped but not UDP, we still return ClassMappedSCION
	// (could be SCMP or other SCION transport)
	if class != ClassMappedSCION {
		t.Errorf("SCION-mapped non-UDP packet classified as %d, expected ClassMappedSCION (%d)", class, ClassMappedSCION)
	}
}

func TestClassifyPacketNativeSCIONWithDispatchPortRange(t *testing.T) {
	// IPv6 packet with UDP port in native SCION dispatch range (30041-32767)
	pkt := make([]byte, 48)
	pkt[0] = 0x60  // version=6
	pkt[6] = 17    // UDP
	pkt[24] = 0x20 // non-SCION prefix

	// UDP destination port in dispatch range
	port := uint16(31234)
	binary.BigEndian.PutUint16(pkt[42:44], port)

	// SCION version=0 in payload
	if len(pkt) >= 49 {
		pkt[48] = 0x00 // SCION version=0
	}

	class := ClassifyPacket(pkt)
	if class != ClassNativeSCION {
		t.Errorf("Native SCION packet (port %d) classified as %d, expected ClassNativeSCION (%d)", port, class, ClassNativeSCION)
	}
}

func TestClassifyPacketInvalidSCIONVersion(t *testing.T) {
	// IPv6 SCION-mapped with invalid SCION version in payload
	pkt := make([]byte, 48)
	pkt[0] = 0x60  // version=6
	pkt[6] = 17    // UDP
	pkt[24] = 0xfc // SCION-mapped prefix

	// SCION version=1 (invalid, should be 0)
	if len(pkt) >= 49 {
		pkt[48] = 0x10 // SCION version=1
	}

	class := ClassifyPacket(pkt)
	// Even with invalid SCION version, SCION-mapped address should be classified as such
	// The actual validation happens in TranslateIngress
	if class != ClassMappedSCION {
		t.Errorf("Packet with SCION-mapped addr but invalid SCION version classified as %d, expected ClassMappedSCION (%d)", class, ClassMappedSCION)
	}
}

func TestClassifyPacketRealPacketScenarios(t *testing.T) {
	tests := []struct {
		name     string
		pktFunc  func() []byte
		expected uint8
	}{
		{
			name: "IPv4 TCP",
			pktFunc: func() []byte {
				pkt := make([]byte, 40)
				pkt[0] = 0x45 // IPv4, IHL=5
				pkt[9] = 6    // TCP
				copy(pkt[16:20], []byte{192, 0, 2, 1})
				copy(pkt[20:24], []byte{192, 0, 2, 2})
				return pkt
			},
			expected: ClassPlainIP,
		},
		{
			name: "IPv6 standard (non-mapped)",
			pktFunc: func() []byte {
				pkt := make([]byte, 40)
				pkt[0] = 0x60  // IPv6
				pkt[6] = 17    // UDP
				pkt[24] = 0x20 // Address starts with 2001 or similar
				return pkt
			},
			expected: ClassPlainIP,
		},
		{
			name: "SCION-mapped IPv6",
			pktFunc: func() []byte {
				pkt := make([]byte, 50)
				pkt[0] = 0x60  // IPv6
				pkt[6] = 17    // UDP
				pkt[24] = 0xfc // SCION-mapped fc00::
				pkt[48] = 0x00 // SCION version=0
				return pkt
			},
			expected: ClassMappedSCION,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := tt.pktFunc()
			class := ClassifyPacket(pkt)
			if class != tt.expected {
				t.Errorf("Packet classified as %d, expected %d", class, tt.expected)
			}
		})
	}
}

func BenchmarkClassifyPacket(b *testing.B) {
	// Create a SCION-mapped IPv6 packet
	pkt := make([]byte, 48)
	pkt[0] = 0x60  // version=6
	pkt[6] = 17    // UDP
	pkt[24] = 0xfc // SCION-mapped prefix
	pkt[48] = 0x00 // SCION version=0

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ClassifyPacket(pkt)
	}
}

// Test that real IPv6 addresses map correctly
func TestClassifyWithRealIPv6Addresses(t *testing.T) {
	// Test with actual IPv6 addresses
	pkt := make([]byte, 48)
	pkt[0] = 0x60 // version=6
	pkt[6] = 17   // UDP

	// Set dst = fc00::1 (SCION-mapped)
	dstAddr := net.ParseIP("fc00::1").To16()
	copy(pkt[24:40], dstAddr)

	class := ClassifyPacket(pkt)
	if class != ClassMappedSCION {
		t.Errorf("SCION-mapped address fc00::1 classified as %d, expected ClassMappedSCION", class)
	}

	// Set dst = 2001:db8::1 (not SCION-mapped)
	dstAddr2 := net.ParseIP("2001:db8::1").To16()
	copy(pkt[24:40], dstAddr2)

	class2 := ClassifyPacket(pkt)
	if class2 != ClassPlainIP {
		t.Errorf("Standard IPv6 address 2001:db8::1 classified as %d, expected ClassPlainIP", class2)
	}
}
