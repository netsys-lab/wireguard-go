package flow

import (
	"net/netip"
	"testing"
)

func TestTrafficClassPlainIP(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion:    4,
		Protocol:     ProtocolTCP,
		Source:       Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 1000},
		Destination:  Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 80},
		TrafficClass: ClassPlainIP,
	}
	snap, created := m.ObserveTx(md, 100, EgressIP)
	if !created {
		t.Fatal("expected created")
	}
	if snap.TrafficClass != ClassPlainIP {
		t.Fatalf("expected PlainIP, got %d", snap.TrafficClass)
	}
	if snap.EgressKind != EgressIP {
		t.Fatalf("expected ip, got %s", snap.EgressKind)
	}
}

func TestTrafficClassMappedSCION(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion:    6,
		Protocol:     ProtocolTCP,
		Source:       Endpoint{Addr: netip.MustParseAddr("fd42:42:42::70"), Port: 52734},
		Destination:  Endpoint{Addr: netip.MustParseAddr("fc00:10fb:f000::1"), Port: 8000},
		SrcIA:        "1-ff00:0:110",
		DstIA:        "2-ff00:0:111",
		SCIONDstIP:   netip.MustParseAddr("10.30.34.100"),
		TrafficClass: ClassMappedSCION,
	}
	snap, created := m.ObserveTx(md, 100, EgressSCION)
	if !created {
		t.Fatal("expected created")
	}
	if snap.TrafficClass != ClassMappedSCION {
		t.Fatalf("expected Mapped, got %d", snap.TrafficClass)
	}
	if snap.EgressKind != EgressSCION {
		t.Fatalf("expected scion, got %s", snap.EgressKind)
	}
}

func TestTrafficClassNativeSCION(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion:    4,
		Protocol:     ProtocolUDP,
		Source:       Endpoint{Addr: netip.MustParseAddr("10.44.25.1"), Port: 30041},
		Destination:  Endpoint{Addr: netip.MustParseAddr("10.30.34.100"), Port: 30041},
		SrcIA:        "1-ff00:0:110",
		DstIA:        "2-ff00:0:111",
		TrafficClass: ClassNativeSCION,
	}
	snap, created := m.ObserveTx(md, 100, EgressSCION)
	if !created {
		t.Fatal("expected created")
	}
	if snap.TrafficClass != ClassNativeSCION {
		t.Fatalf("expected Native, got %d", snap.TrafficClass)
	}
}

func TestTrafficClassFirstWriterWins(t *testing.T) {
	m := NewManager()
	md1 := PacketMetadata{
		IPVersion:    6,
		Protocol:     ProtocolTCP,
		Source:       Endpoint{Addr: netip.MustParseAddr("fd42::1"), Port: 1000},
		Destination:  Endpoint{Addr: netip.MustParseAddr("fc00::1"), Port: 80},
		TrafficClass: ClassMappedSCION,
	}
	snap1, _ := m.ObserveTx(md1, 100, EgressSCION)
	if snap1.TrafficClass != ClassMappedSCION {
		t.Fatalf("expected Mapped, got %d", snap1.TrafficClass)
	}
	// Second packet with different class should not overwrite
	md2 := md1
	md2.TrafficClass = ClassNativeSCION
	snap2, created := m.ObserveTx(md2, 100, EgressSCION)
	if created {
		t.Fatal("expected not created")
	}
	if snap2.TrafficClass != ClassMappedSCION {
		t.Fatalf("expected still Mapped after second, got %d", snap2.TrafficClass)
	}
}

func TestSnapshotExposesTrafficClass(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion:    6,
		Protocol:     ProtocolTCP,
		Source:       Endpoint{Addr: netip.MustParseAddr("fd42::1"), Port: 1000},
		Destination:  Endpoint{Addr: netip.MustParseAddr("fc00::1"), Port: 80},
		TrafficClass: ClassMappedSCION,
	}
	snap, _ := m.ObserveTx(md, 100, EgressSCION)
	dto := MapSnapshotToDTO(snap)
	if dto.TrafficClass != uint8(ClassMappedSCION) {
		t.Fatalf("DTO expected %d, got %d", ClassMappedSCION, dto.TrafficClass)
	}
}
