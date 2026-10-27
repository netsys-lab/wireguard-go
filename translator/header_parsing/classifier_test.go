package header_parsing

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestClassifierWithRealDataPackets verifies classification using real, serialized
// SCION and Mapped test packets from translator/data/*.bin.
func TestClassifierWithRealDataPackets(t *testing.T) {
	testFiles := []struct {
		name       string
		file       string
		innerIndex int
		outerIndex int
		outerDesc  string
	}{
		{
			name:       "IPv4 UDP SCION",
			file:       "../data/translate_udp_ipv4.bin",
			innerIndex: 0,
			outerIndex: 1,
			outerDesc:  "IPv4/UDP/SCION",
		},
		{
			name:       "IPv6 UDP SCION",
			file:       "../data/translate_udp_ipv6.bin",
			innerIndex: 0,
			outerIndex: 1,
			outerDesc:  "IPv6/UDP/SCION",
		},
		{
			name:       "IPv4 TCP SCION",
			file:       "../data/translate_tcp_ipv4.bin",
			innerIndex: 0,
			outerIndex: 2, // In translate_tcp_ipv4.bin, pkts[0]=input, pkts[1]=clamped_input, pkts[2]=translated_scion
			outerDesc:  "IPv4/UDP/SCION (TCP inside)",
		},
	}

	for _, tc := range testFiles {
		t.Run(tc.name, func(t *testing.T) {
			pkts := LoadPackets(t, tc.file)
			if len(pkts) <= tc.outerIndex {
				t.Fatalf("expected at least %d packets in %s, got %d", tc.outerIndex+1, tc.file, len(pkts))
			}

			innerMapped := pkts[tc.innerIndex]
			outerSCION := pkts[tc.outerIndex]

			// 1. Test inner packet before translation:
			// It has a mapped destination (fc00::) and should be classified as ClassMappedSCION on egress.
			if got := ClassifyEgress(innerMapped); got != ClassMappedSCION {
				t.Errorf("inner mapped packet ClassifyEgress = %d, expected ClassMappedSCION (%d)", got, ClassMappedSCION)
			}
			// Inner mapped packet is plain IP before WireGuard/SCION encapsulation, so ingress should be ClassPlainIP.
			if got := ClassifyIngress(innerMapped); got != ClassPlainIP {
				t.Errorf("inner mapped packet ClassifyIngress = %d, expected ClassPlainIP (%d)", got, ClassPlainIP)
			}
			if isValidOuterSCION(innerMapped) {
				t.Errorf("inner mapped packet should not be valid outer SCION")
			}

			// 2. Test outer SCION packet after translation:
			// Outer packet has valid IP/UDP/SCION headers.
			if !isValidOuterSCION(outerSCION) {
				t.Errorf("real %s packet rejected by isValidOuterSCION", tc.outerDesc)
			}
			if got := ClassifyEgress(outerSCION); got != ClassNativeSCION {
				t.Errorf("real %s packet ClassifyEgress = %d, expected ClassNativeSCION (%d)", tc.outerDesc, got, ClassNativeSCION)
			}
			if got := ClassifyIngress(outerSCION); got != ClassNativeSCION {
				t.Errorf("real %s packet ClassifyIngress = %d, expected ClassNativeSCION (%d)", tc.outerDesc, got, ClassNativeSCION)
			}
		})
	}
}

// TestClassifierWithPlainNonSCIONPackets tests non-SCION traffic:
// regular web browsing, DNS, ICMP, and false-positive candidates.
func TestClassifierWithPlainNonSCIONPackets(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
	}{
		{
			name: "Standard IPv4 TCP (HTTP/HTTPS to 93.184.216.34)",
			packet: func() []byte {
				pkt := make([]byte, 40)
				pkt[0] = 0x45 // IPv4, IHL=5
				pkt[9] = 6    // TCP
				copy(pkt[12:16], net.ParseIP("192.168.1.100").To4())
				copy(pkt[16:20], net.ParseIP("93.184.216.34").To4())
				binary.BigEndian.PutUint16(pkt[20:22], 54321) // src port
				binary.BigEndian.PutUint16(pkt[22:24], 443)   // dst port
				return pkt
			}(),
		},
		{
			name: "Standard IPv4 UDP (DNS query to 8.8.8.8:53 with non-SCION payload)",
			packet: func() []byte {
				payload := []byte("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
				pkt := make([]byte, 20+8+len(payload))
				pkt[0] = 0x45 // IPv4, IHL=5
				binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
				pkt[9] = 17 // UDP
				copy(pkt[12:16], net.ParseIP("192.168.1.100").To4())
				copy(pkt[16:20], net.ParseIP("8.8.8.8").To4())
				binary.BigEndian.PutUint16(pkt[20:22], 49152) // src port
				binary.BigEndian.PutUint16(pkt[22:24], 53)    // dst port 53 (DNS)
				binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
				copy(pkt[28:], payload)
				return pkt
			}(),
		},
		{
			name: "Standard IPv6 TCP (HTTP to 2001:db8::1:80)",
			packet: func() []byte {
				pkt := make([]byte, 60)
				pkt[0] = 0x60 // IPv6
				pkt[6] = 6    // TCP
				copy(pkt[8:24], net.ParseIP("2001:db8::100").To16())
				copy(pkt[24:40], net.ParseIP("2001:db8::1").To16())
				binary.BigEndian.PutUint16(pkt[40:42], 50000)
				binary.BigEndian.PutUint16(pkt[42:44], 80)
				return pkt
			}(),
		},
		{
			name: "Standard IPv6 UDP (non-SCION, non-fc00)",
			packet: func() []byte {
				pkt := make([]byte, 40+8+10)
				pkt[0] = 0x60
				pkt[6] = 17 // UDP
				copy(pkt[8:24], net.ParseIP("2001:db8::100").To16())
				copy(pkt[24:40], net.ParseIP("2001:db8::1").To16())
				binary.BigEndian.PutUint16(pkt[40:42], 40000)
				binary.BigEndian.PutUint16(pkt[42:44], 53)
				copy(pkt[48:], []byte("dnsquery.."))
				return pkt
			}(),
		},
		{
			name: "IPv4 UDP on SCION Router Port (31002) but random non-SCION payload",
			packet: func() []byte {
				pkt := make([]byte, 20+8+16)
				pkt[0] = 0x45
				pkt[9] = 17
				binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
				binary.BigEndian.PutUint16(pkt[22:24], 31002) // router port
				// Payload does NOT start with SCION version 0 nibble (0x10 = version 1)
				pkt[28] = 0x10
				copy(pkt[29:], []byte("not-scion-packet"))
				return pkt
			}(),
		},
		{
			name: "IPv6 UDP on Endhost Port (30041) with non-SCION payload (version 2)",
			packet: func() []byte {
				pkt := make([]byte, 40+8+10)
				pkt[0] = 0x60
				pkt[6] = 17
				binary.BigEndian.PutUint16(pkt[42:44], DefaultSCIONEndhostPort)
				pkt[48] = 0x20 // SCION version 2 (invalid)
				copy(pkt[49:], []byte("invalid-sc"))
				return pkt
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if isValidOuterSCION(tt.packet) {
				t.Errorf("isValidOuterSCION should return false for plain packet %s", tt.name)
			}
			if got := ClassifyEgress(tt.packet); got != ClassPlainIP {
				t.Errorf("ClassifyEgress(%s) = %d, expected ClassPlainIP (%d)", tt.name, got, ClassPlainIP)
			}
			if got := ClassifyIngress(tt.packet); got != ClassPlainIP {
				t.Errorf("ClassifyIngress(%s) = %d, expected ClassPlainIP (%d)", tt.name, got, ClassPlainIP)
			}
		})
	}
}

// TestClassifierMalformedAndTruncatedPackets ensures no panic on edge cases.
func TestClassifierMalformedAndTruncatedPackets(t *testing.T) {
	edgeCases := [][]byte{
		{},
		{0x45},
		{0x45, 0x00},
		make([]byte, 19), // just below 20 bytes
		func() []byte {
			pkt := make([]byte, 20)
			pkt[0] = 0x4f // IHL=15 -> 60 bytes, but packet only 20
			return pkt
		}(),
		func() []byte {
			pkt := make([]byte, 20)
			pkt[0] = 0x45
			pkt[9] = 17 // UDP, but len < 28
			return pkt
		}(),
		func() []byte {
			pkt := make([]byte, 28)
			pkt[0] = 0x45
			pkt[9] = 17 // UDP, exactly 28 bytes, 0 bytes payload
			return pkt
		}(),
		make([]byte, 39), // IPv6 truncated (< 40)
		func() []byte {
			pkt := make([]byte, 40)
			pkt[0] = 0x60
			pkt[6] = 17 // IPv6 UDP, but 0 bytes UDP header
			return pkt
		}(),
		func() []byte {
			pkt := make([]byte, 48)
			pkt[0] = 0x60
			pkt[6] = 17 // IPv6 UDP, exactly 48 bytes, 0 bytes payload
			return pkt
		}(),
		{0x20, 0x00, 0x00, 0x00}, // Version 2 (unknown)
	}

	for i, pkt := range edgeCases {
		if isValidOuterSCION(pkt) {
			t.Errorf("edge case %d: isValidOuterSCION should be false", i)
		}
		if got := ClassifyEgress(pkt); got != ClassPlainIP {
			t.Errorf("edge case %d: ClassifyEgress should be ClassPlainIP, got %d", i, got)
		}
		if got := ClassifyIngress(pkt); got != ClassPlainIP {
			t.Errorf("edge case %d: ClassifyIngress should be ClassPlainIP, got %d", i, got)
		}
	}
}
