package header_parsing

import (
	"encoding/binary"
	"testing"
)

func TestClassifyEgressPlainIPv4(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	pkt[9] = 6
	if got := ClassifyEgress(pkt); got != ClassPlainIP {
		t.Fatalf("expected Plain, got %d", got)
	}
}

func TestClassifyEgressPlainIPv6(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = 0x60
	pkt[6] = 6
	pkt[24] = 0x20
	if got := ClassifyEgress(pkt); got != ClassPlainIP {
		t.Fatalf("expected Plain, got %d", got)
	}
}

func TestClassifyEgressMappedIPv6(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = 0x60
	pkt[6] = 6
	pkt[24] = 0xfc
	if got := ClassifyEgress(pkt); got != ClassMappedSCION {
		t.Fatalf("expected Mapped, got %d", got)
	}
	// UDP variant
	pkt2 := make([]byte, 40)
	pkt2[0] = 0x60
	pkt2[6] = 17
	pkt2[24] = 0xfc
	if got := ClassifyEgress(pkt2); got != ClassMappedSCION {
		t.Fatalf("expected Mapped UDP, got %d", got)
	}
}

func TestClassifyEgressNativeIPv4(t *testing.T) {
	// IPv4/UDP/SCION with accepted port 30041 ver0
	pkt := make([]byte, 20+8+1)
	pkt[0] = 0x45
	pkt[0] = (4 << 4) | 5 // version 4 IHL 5
	pkt[9] = 17           // UDP
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[20+2] = byte(DefaultSCIONEndhostPort >> 8)
	pkt[20+3] = byte(DefaultSCIONEndhostPort & 0xff)
	pkt[20+8] = 0x00 // SCION ver 0
	if got := ClassifyEgress(pkt); got != ClassNativeSCION {
		t.Fatalf("expected Native IPv4, got %d", got)
	}
}

func TestClassifyEgressNativeIPv6(t *testing.T) {
	pkt := make([]byte, 40+8+1)
	pkt[0] = 0x60
	pkt[6] = 17
	binary.BigEndian.PutUint16(pkt[42:44], DefaultSCIONEndhostPort)
	pkt[48] = 0x00
	if got := ClassifyEgress(pkt); got != ClassNativeSCION {
		t.Fatalf("expected Native IPv6, got %d", got)
	}
}

func TestClassifyEgressWrongNativePort(t *testing.T) {
	pkt := make([]byte, 40+8+1)
	pkt[0] = 0x60
	pkt[6] = 17
	binary.BigEndian.PutUint16(pkt[42:44], 8001) // not accepted
	pkt[48] = 0x00
	if got := ClassifyEgress(pkt); got == ClassNativeSCION {
		t.Fatalf("expected not Native for wrong port, got %d", got)
	}
	if got := ClassifyEgress(pkt); got != ClassPlainIP {
		t.Fatalf("expected Plain for wrong port, got %d", got)
	}
}

func TestClassifyEgressInvalidSCIONVersion(t *testing.T) {
	pkt := make([]byte, 40+8+1)
	pkt[0] = 0x60
	pkt[6] = 17
	binary.BigEndian.PutUint16(pkt[42:44], DefaultSCIONEndhostPort)
	pkt[48] = 0x10 // ver 1
	if got := ClassifyEgress(pkt); got == ClassNativeSCION {
		t.Fatalf("expected not Native for invalid ver")
	}
}

func TestClassifyEgressMalformed(t *testing.T) {
	pkt := make([]byte, 10)
	pkt[0] = 0x60
	if got := ClassifyEgress(pkt); got != ClassPlainIP {
		t.Fatalf("expected Plain for malformed")
	}
}

func TestClassifyIngressPlainVsSCION(t *testing.T) {
	plain := make([]byte, 40)
	plain[0] = 0x60
	plain[6] = 6
	plain[24] = 0x20
	if got := ClassifyIngress(plain); got != ClassPlainIP {
		t.Fatalf("plain ingress expected Plain, got %d", got)
	}
	// Native SCION ingress
	scion := make([]byte, 40+8+1)
	scion[0] = 0x60
	scion[6] = 17
	binary.BigEndian.PutUint16(scion[42:44], DefaultSCIONEndhostPort)
	scion[48] = 0x00
	if got := ClassifyIngress(scion); got == ClassPlainIP {
		t.Fatalf("expected SCION on ingress, got Plain")
	}
}

func TestIsNativeSCIONPort(t *testing.T) {
	if !isNativeSCIONPort(DefaultSCIONEndhostPort) {
		t.Fatal("30041 should be accepted")
	}
	if isNativeSCIONPort(8001) {
		t.Fatal("8001 should not be accepted as native")
	}
}

func TestIsTranslatedIngressPort(t *testing.T) {
	if !IsTranslatedIngressPort(8000) {
		t.Fatal("8000 should be allowed")
	}
	if IsTranslatedIngressPort(8001) {
		t.Fatal("8001 should not be allowed")
	}
}
