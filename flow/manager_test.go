package flow

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestFirstPacketCreatesFlowID1(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}

	snap, created := m.ObserveTx(md, 100, EgressIP)
	if !created {
		t.Fatal("expected new flow to be created")
	}
	if snap.ID != 1 {
		t.Errorf("expected ID 1, got %d", snap.ID)
	}
}

func TestSameTupleUpdatesSameFlow(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}

	snap1, created := m.ObserveTx(md, 100, EgressIP)
	if !created {
		t.Fatal("expected first to create")
	}
	if snap1.TxPackets != 1 {
		t.Errorf("expected 1 tx packet, got %d", snap1.TxPackets)
	}
	if snap1.TxBytes != 100 {
		t.Errorf("expected 100 tx bytes, got %d", snap1.TxBytes)
	}

	snap2, created := m.ObserveTx(md, 200, EgressIP)
	if created {
		t.Fatal("expected second to NOT create new flow")
	}
	if snap2.ID != snap1.ID {
		t.Errorf("expected same ID %d, got %d", snap1.ID, snap2.ID)
	}
	if snap2.TxPackets != 2 {
		t.Errorf("expected 2 tx packets, got %d", snap2.TxPackets)
	}
	if snap2.TxBytes != 300 {
		t.Errorf("expected 300 tx bytes, got %d", snap2.TxBytes)
	}
}

func TestReverseDirectionSameFlow(t *testing.T) {
	m := NewManager()

	md1 := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}
	snap1, created := m.ObserveTx(md1, 100, EgressIP)
	if !created {
		t.Fatal("expected first to create")
	}

	md2 := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
	}
	snap2, created := m.ObserveRx(md2, 200, EgressIP)
	if created {
		t.Fatal("expected reverse to NOT create new flow")
	}
	if snap2.ID != snap1.ID {
		t.Errorf("expected same ID %d, got %d", snap1.ID, snap2.ID)
	}
	if snap2.TxPackets != 1 {
		t.Errorf("expected 1 tx packet, got %d", snap2.TxPackets)
	}
	if snap2.RxPackets != 1 {
		t.Errorf("expected 1 rx packet, got %d", snap2.RxPackets)
	}
}

func TestDifferentPortDifferentFlow(t *testing.T) {
	m := NewManager()
	baseMD := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}
	diffPortMD := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49153},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}

	snap1, _ := m.ObserveTx(baseMD, 100, EgressIP)
	snap2, _ := m.ObserveTx(diffPortMD, 100, EgressIP)

	if snap1.ID == snap2.ID {
		t.Errorf("expected different flow IDs for different ports, got both %d", snap1.ID)
	}
}

func TestTCPvUDPDifferentFlows(t *testing.T) {
	m := NewManager()
	tcpMD := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}
	udpMD := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolUDP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}

	snap1, _ := m.ObserveTx(tcpMD, 100, EgressIP)
	snap2, _ := m.ObserveTx(udpMD, 100, EgressIP)

	if snap1.ID == snap2.ID {
		t.Errorf("expected different flows for TCP vs UDP, got both %d", snap1.ID)
	}
}

func TestIPv4v6DistinctFlows(t *testing.T) {
	m := NewManager()
	ipv4MD := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}
	ipv6MD := PacketMetadata{
		IPVersion: 6,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("::ffff:a00:2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("::ffff:a00:3"), Port: 443},
	}

	snap1, _ := m.ObserveTx(ipv4MD, 100, EgressIP)
	snap2, _ := m.ObserveTx(ipv6MD, 100, EgressIP)

	if snap1.ID == snap2.ID {
		t.Errorf("expected different flows for IPv4 vs IPv6, got both %d", snap1.ID)
	}
}

func TestObserveTxIncrementsTxOnly(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}

	snap, _ := m.ObserveTx(md, 100, EgressIP)
	if snap.TxPackets != 1 {
		t.Errorf("TxPackets: got %d, want 1", snap.TxPackets)
	}
	if snap.TxBytes != 100 {
		t.Errorf("TxBytes: got %d, want 100", snap.TxBytes)
	}
	if snap.RxPackets != 0 {
		t.Errorf("RxPackets: got %d, want 0", snap.RxPackets)
	}
	if snap.RxBytes != 0 {
		t.Errorf("RxBytes: got %d, want 0", snap.RxBytes)
	}

	snap2, _ := m.ObserveTx(md, 200, EgressIP)
	if snap2.TxPackets != 2 {
		t.Errorf("TxPackets: got %d, want 2", snap2.TxPackets)
	}
	if snap2.TxBytes != 300 {
		t.Errorf("TxBytes: got %d, want 300", snap2.TxBytes)
	}
	if snap2.RxPackets != 0 {
		t.Errorf("RxPackets: got %d, want 0", snap2.RxPackets)
	}
}

func TestObserveRxIncrementsRxOnly(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}

	snap, _ := m.ObserveRx(md, 100, EgressIP)
	if snap.RxPackets != 1 {
		t.Errorf("RxPackets: got %d, want 1", snap.RxPackets)
	}
	if snap.RxBytes != 100 {
		t.Errorf("RxBytes: got %d, want 100", snap.RxBytes)
	}
	if snap.TxPackets != 0 {
		t.Errorf("TxPackets: got %d, want 0", snap.TxPackets)
	}
	if snap.TxBytes != 0 {
		t.Errorf("TxBytes: got %d, want 0", snap.TxBytes)
	}
}

func TestPacketByteCounters(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}

	total := 0
	for _, length := range []int{100, 200, 300} {
		snap, _ := m.ObserveTx(md, length, EgressIP)
		_ = snap
		total += length
	}

	snap := m.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(snap))
	}
	if snap[0].TxBytes != uint64(total) {
		t.Errorf("TxBytes: got %d, want %d", snap[0].TxBytes, total)
	}
	if snap[0].TxPackets != 3 {
		t.Errorf("TxPackets: got %d, want 3", snap[0].TxPackets)
	}
}

func TestCreatedAtStableLastSeenUpdated(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}

	snap1, _ := m.ObserveTx(md, 100, EgressIP)

	time.Sleep(time.Millisecond)

	snap2, _ := m.ObserveTx(md, 200, EgressIP)

	if !snap1.CreatedAt.Equal(snap2.CreatedAt) {
		t.Errorf("CreatedAt changed: was %v, now %v", snap1.CreatedAt, snap2.CreatedAt)
	}
	if !snap2.LastSeen.After(snap1.LastSeen) {
		t.Errorf("LastSeen should have advanced: was %v, now %v", snap1.LastSeen, snap2.LastSeen)
	}
}

func TestSnapshotReturnsCopiesSortedByID(t *testing.T) {
	m := NewManager()
	mds := []PacketMetadata{
		{4, ProtocolTCP, Endpoint{netip.MustParseAddr("10.0.0.1"), 100}, Endpoint{netip.MustParseAddr("10.0.0.2"), 200}},
		{4, ProtocolTCP, Endpoint{netip.MustParseAddr("10.0.0.3"), 300}, Endpoint{netip.MustParseAddr("10.0.0.4"), 400}},
		{4, ProtocolUDP, Endpoint{netip.MustParseAddr("10.0.0.5"), 500}, Endpoint{netip.MustParseAddr("10.0.0.6"), 600}},
	}

	for _, md := range mds {
		m.ObserveTx(md, 100, EgressIP)
	}

	snaps := m.Snapshot()
	if len(snaps) != 3 {
		t.Fatalf("expected 3 flows, got %d", len(snaps))
	}

	for i := 1; i < len(snaps); i++ {
		if snaps[i].ID <= snaps[i-1].ID {
			t.Errorf("snapshots not sorted by ID: snaps[%d].ID=%d <= snaps[%d].ID=%d",
				i-1, snaps[i-1].ID, i, snaps[i].ID)
		}
	}

	beforeTx := m.Snapshot()[0].TxPackets
	m.ObserveTx(mds[0], 200, EgressIP)
	afterTx := m.Snapshot()[0].TxPackets
	if afterTx != beforeTx+1 {
		t.Errorf("expected TxPackets to increase by 1; before=%d, after=%d", beforeTx, afterTx)
	}
}

func TestEgressKindModel(t *testing.T) {
	if EgressUnknown != "unknown" {
		t.Errorf("EgressUnknown = %q, want %q", EgressUnknown, "unknown")
	}
	if EgressIP != "ip" {
		t.Errorf("EgressIP = %q, want %q", EgressIP, "ip")
	}
	if EgressSCION != "scion" {
		t.Errorf("EgressSCION = %q, want %q", EgressSCION, "scion")
	}
}

func TestNewIPFlowStoresEgressIP(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}
	snap, _ := m.ObserveTx(md, 100, EgressIP)
	if snap.EgressKind != EgressIP {
		t.Errorf("EgressKind = %q, want %q", snap.EgressKind, EgressIP)
	}
}

func TestNewSCIONFlowStoresEgressSCION(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion: 6,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("fd42:42:42::70"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("fc04:7800:4a00::ffff:a2c:1947"), Port: 443},
	}
	snap, _ := m.ObserveTx(md, 100, EgressSCION)
	if snap.EgressKind != EgressSCION {
		t.Errorf("EgressKind = %q, want %q", snap.EgressKind, EgressSCION)
	}
}

func TestRepeatedPacketPreservesClassification(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}
	snap1, _ := m.ObserveTx(md, 100, EgressIP)
	snap2, _ := m.ObserveTx(md, 200, EgressIP)
	if snap2.EgressKind != EgressIP {
		t.Errorf("second observation EgressKind = %q, want %q", snap2.EgressKind, EgressIP)
	}
	if snap1.EgressKind != snap2.EgressKind {
		t.Errorf("classification changed: %q -> %q", snap1.EgressKind, snap2.EgressKind)
	}
}

func TestIPNotOverwrittenBySCION(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}
	snap1, _ := m.ObserveTx(md, 100, EgressIP)
	// Observe with SCION on the same flow — must not overwrite
	snap2, _ := m.ObserveTx(md, 200, EgressSCION)
	if snap2.EgressKind != EgressIP {
		t.Errorf("IP flow overwritten to %q, want %q", snap2.EgressKind, EgressIP)
	}
	if snap1.ID != snap2.ID {
		t.Errorf("same flow got different IDs: %d vs %d", snap1.ID, snap2.ID)
	}
}

func TestDifferentFlowsDifferentEgressKind(t *testing.T) {
	m := NewManager()
	ipMD := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}
	scionMD := PacketMetadata{
		IPVersion: 6,
		Protocol:  ProtocolUDP,
		Source:      Endpoint{Addr: netip.MustParseAddr("fd42:42:42::70"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("fc04:7800:4a00::ffff:a2c:1947"), Port: 443},
	}
	snap1, _ := m.ObserveTx(ipMD, 100, EgressIP)
	snap2, _ := m.ObserveTx(scionMD, 100, EgressSCION)
	if snap1.ID == snap2.ID {
		t.Error("IP and SCION flows should have different IDs")
	}
	if snap1.EgressKind != EgressIP {
		t.Errorf("IP flow EgressKind = %q, want %q", snap1.EgressKind, EgressIP)
	}
	if snap2.EgressKind != EgressSCION {
		t.Errorf("SCION flow EgressKind = %q, want %q", snap2.EgressKind, EgressSCION)
	}
}

func TestSnapshotContainsEgressKind(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}
	m.ObserveTx(md, 100, EgressIP)
	snaps := m.Snapshot()
	if len(snaps) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(snaps))
	}
	if snaps[0].EgressKind != EgressIP {
		t.Errorf("snapshot EgressKind = %q, want %q", snaps[0].EgressKind, EgressIP)
	}
}

func TestUnknownPromotedToIP(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}
	// Create with unknown, then promote to IP
	snap1, _ := m.ObserveTx(md, 100, EgressUnknown)
	snap2, _ := m.ObserveTx(md, 200, EgressIP)
	if snap2.EgressKind != EgressIP {
		t.Errorf("unknown should be promoted to IP, got %q", snap2.EgressKind)
	}
	_ = snap1
}

func TestReverseDirectionSameEgressKind(t *testing.T) {
	m := NewManager()
	txMD := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}
	snap1, _ := m.ObserveTx(txMD, 100, EgressIP)

	rxMD := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
	}
	snap2, _ := m.ObserveRx(rxMD, 200, EgressIP)

	if snap2.ID != snap1.ID {
		t.Errorf("expected same flow ID for reverse direction: %d vs %d", snap1.ID, snap2.ID)
	}
	if snap2.EgressKind != EgressIP {
		t.Errorf("reverse direction EgressKind = %q, want %q", snap2.EgressKind, EgressIP)
	}
}

func TestConcurrentObservations(t *testing.T) {
	m := NewManager()
	md := PacketMetadata{
		IPVersion: 4,
		Protocol:  ProtocolTCP,
		Source:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		Destination: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
	}

	const goroutines = 50
	const observationsPer = 20

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < observationsPer; j++ {
				m.ObserveTx(md, 100, EgressIP)
			}
		}()
	}
	wg.Wait()

	snaps := m.Snapshot()
	if len(snaps) != 1 {
		t.Errorf("expected exactly 1 flow, got %d (duplicate flows)", len(snaps))
		return
	}
	expected := goroutines * observationsPer
	if snaps[0].TxPackets != uint64(expected) {
		t.Errorf("expected %d tx packets, got %d", expected, snaps[0].TxPackets)
	}
	if snaps[0].TxBytes != uint64(expected*100) {
		t.Errorf("expected %d tx bytes, got %d", expected*100, snaps[0].TxBytes)
	}
}
