package device

import (
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"golang.zx2c4.com/wireguard/flow"
)

func TestSCIONFlowIndexHIT(t *testing.T) {
	d := &Device{
		flowManager: flow.NewManager(),
	}
	// create a mapped flow
	md := flow.PacketMetadata{
		IPVersion:    6,
		Protocol:     flow.ProtocolTCP,
		Source:       flow.Endpoint{Addr: netip.MustParseAddr("fd42:42:42::70"), Port: 52734},
		Destination:  flow.Endpoint{Addr: netip.MustParseAddr("fc00:10fb:f000::1"), Port: 8000},
		TrafficClass: flow.ClassMappedSCION,
		SrcIA:        "1-ff00:0:110",
		DstIA:        "2-ff00:0:111",
	}
	snap, _ := d.flowManager.ObserveTx(md, 100, flow.EgressSCION)
	srcIA := addr.MustIAFrom(1, 0xff0000000110)
	dstIA := addr.MustIAFrom(2, 0xff0000000111)
	srcHost := netip.MustParseAddr("10.44.25.1")
	dstHost := netip.MustParseAddr("10.30.34.100")
	d.rememberSCIONFlow(snap.ID, flow.ProtocolTCP, srcIA, dstIA, srcHost, dstHost, 52734, 8000)
	// lookup reverse Y->X
	snap2, res := d.lookupSCIONFlow(flow.ProtocolTCP, dstIA, srcIA, dstHost, srcHost, 8000, 52734)
	if res != SCIONLookupHit {
		t.Fatalf("expected HIT, got %v", res)
	}
	if snap2.ID != snap.ID {
		t.Fatalf("expected flow %d, got %d", snap.ID, snap2.ID)
	}
	if snap2.TrafficClass != flow.ClassMappedSCION {
		t.Fatalf("expected mapped")
	}
}

func TestSCIONFlowIndexMISS(t *testing.T) {
	d := &Device{
		flowManager: flow.NewManager(),
	}
	srcIA := addr.MustIAFrom(1, 1)
	dstIA := addr.MustIAFrom(2, 2)
	srcHost := netip.MustParseAddr("10.0.0.1")
	dstHost := netip.MustParseAddr("10.0.0.2")
	_, res := d.lookupSCIONFlow(flow.ProtocolTCP, srcIA, dstIA, srcHost, dstHost, 1234, 80)
	if res != SCIONLookupMiss {
		t.Fatalf("expected MISS, got %v", res)
	}
}

func TestSCIONFlowIndexAmbiguous(t *testing.T) {
	d := &Device{
		flowManager: flow.NewManager(),
	}
	srcIA := addr.MustIAFrom(1, 1)
	dstIA := addr.MustIAFrom(2, 2)
	srcHost := netip.MustParseAddr("10.44.25.1")
	dstHost := netip.MustParseAddr("10.30.34.100")
	// two flows same SCION tuple but different original A
	md1 := flow.PacketMetadata{
		IPVersion:    6,
		Protocol:     flow.ProtocolTCP,
		Source:       flow.Endpoint{Addr: netip.MustParseAddr("fd42::10"), Port: 52734},
		Destination:  flow.Endpoint{Addr: netip.MustParseAddr("fc00::1"), Port: 8000},
		TrafficClass: flow.ClassMappedSCION,
	}
	snap1, _ := d.flowManager.ObserveTx(md1, 100, flow.EgressSCION)
	md2 := flow.PacketMetadata{
		IPVersion:    6,
		Protocol:     flow.ProtocolTCP,
		Source:       flow.Endpoint{Addr: netip.MustParseAddr("fd42::20"), Port: 52734},
		Destination:  flow.Endpoint{Addr: netip.MustParseAddr("fc00::1"), Port: 8000},
		TrafficClass: flow.ClassMappedSCION,
	}
	snap2, _ := d.flowManager.ObserveTx(md2, 100, flow.EgressSCION)
	d.rememberSCIONFlow(snap1.ID, flow.ProtocolTCP, srcIA, dstIA, srcHost, dstHost, 52734, 8000)
	d.rememberSCIONFlow(snap2.ID, flow.ProtocolTCP, srcIA, dstIA, srcHost, dstHost, 52734, 8000)
	_, res := d.lookupSCIONFlow(flow.ProtocolTCP, dstIA, srcIA, dstHost, srcHost, 8000, 52734)
	if res != SCIONLookupAmbiguous {
		t.Fatalf("expected AMBIGUOUS, got %v", res)
	}
}

func TestSCIONFlowIndexCanonical(t *testing.T) {
	d := &Device{
		flowManager: flow.NewManager(),
	}
	srcIA := addr.MustIAFrom(1, 1)
	dstIA := addr.MustIAFrom(2, 2)
	srcHost := netip.MustParseAddr("10.44.25.1")
	dstHost := netip.MustParseAddr("10.30.34.100")
	md := flow.PacketMetadata{
		IPVersion:    6,
		Protocol:     flow.ProtocolUDP,
		Source:       flow.Endpoint{Addr: netip.MustParseAddr("fd42::1"), Port: 1000},
		Destination:  flow.Endpoint{Addr: netip.MustParseAddr("fc00::1"), Port: 2000},
		TrafficClass: flow.ClassMappedSCION,
	}
	snap, _ := d.flowManager.ObserveTx(md, 100, flow.EgressSCION)
	d.rememberSCIONFlow(snap.ID, flow.ProtocolUDP, srcIA, dstIA, srcHost, dstHost, 1000, 2000)
	// lookup forward vs reverse should both hit
	_, res1 := d.lookupSCIONFlow(flow.ProtocolUDP, srcIA, dstIA, srcHost, dstHost, 1000, 2000)
	_, res2 := d.lookupSCIONFlow(flow.ProtocolUDP, dstIA, srcIA, dstHost, srcHost, 2000, 1000)
	if res1 != SCIONLookupHit || res2 != SCIONLookupHit {
		t.Fatalf("expected both HIT, got %v %v", res1, res2)
	}
}

func TestSCMPInfoIndexHIT(t *testing.T) {
	d := &Device{flowManager: flow.NewManager()}
	md := flow.PacketMetadata{
		IPVersion:    6,
		Protocol:     flow.ProtocolICMPv6,
		Source:       flow.Endpoint{Addr: netip.MustParseAddr("fd42::70"), Port: 1234},
		Destination:  flow.Endpoint{Addr: netip.MustParseAddr("fc00::1"), Port: 1234},
		TrafficClass: flow.ClassMappedSCION,
	}
	snap, _ := d.flowManager.ObserveTx(md, 100, flow.EgressSCION)
	localIA := addr.MustIAFrom(1, 1)
	localHost := netip.MustParseAddr("10.44.25.1")
	d.rememberSCMPInfo(snap.ID, 0, localIA, localHost, 32767, 7)
	// lookup via reply's dst (local)
	snap2, res := d.lookupSCMPInfo(0, localIA, localHost, 32767, 7)
	if res != SCIONLookupHit {
		t.Fatalf("expected HIT, got %v", res)
	}
	if snap2.ID != snap.ID {
		t.Fatalf("expected %d, got %d", snap.ID, snap2.ID)
	}
}

func TestSCMPInfoIndexMISS(t *testing.T) {
	d := &Device{flowManager: flow.NewManager()}
	localIA := addr.MustIAFrom(1, 1)
	localHost := netip.MustParseAddr("10.44.25.1")
	_, res := d.lookupSCMPInfo(0, localIA, localHost, 40000, 100)
	if res != SCIONLookupMiss {
		t.Fatalf("expected MISS, got %v", res)
	}
}

func TestSCMPInfoIndexAmbiguous(t *testing.T) {
	d := &Device{flowManager: flow.NewManager()}
	localIA := addr.MustIAFrom(1, 1)
	localHost := netip.MustParseAddr("10.44.25.1")
	md1 := flow.PacketMetadata{IPVersion: 6, Protocol: flow.ProtocolICMPv6, Source: flow.Endpoint{Addr: netip.MustParseAddr("fd42::10"), Port: 1}, Destination: flow.Endpoint{Addr: netip.MustParseAddr("fc00::1"), Port: 1}, TrafficClass: flow.ClassMappedSCION}
	snap1, _ := d.flowManager.ObserveTx(md1, 100, flow.EgressSCION)
	md2 := flow.PacketMetadata{IPVersion: 6, Protocol: flow.ProtocolICMPv6, Source: flow.Endpoint{Addr: netip.MustParseAddr("fd42::20"), Port: 1}, Destination: flow.Endpoint{Addr: netip.MustParseAddr("fc00::1"), Port: 1}, TrafficClass: flow.ClassMappedSCION}
	snap2, _ := d.flowManager.ObserveTx(md2, 100, flow.EgressSCION)
	d.rememberSCMPInfo(snap1.ID, 0, localIA, localHost, 32767, 7)
	d.rememberSCMPInfo(snap2.ID, 0, localIA, localHost, 32767, 7)
	_, res := d.lookupSCMPInfo(0, localIA, localHost, 32767, 7)
	if res != SCIONLookupAmbiguous {
		t.Fatalf("expected AMBIGUOUS, got %v", res)
	}
}

func TestSCMPTracerouteDifferentSrcStillHit(t *testing.T) {
	d := &Device{flowManager: flow.NewManager()}
	localIA := addr.MustIAFrom(1, 1)
	localHost := netip.MustParseAddr("10.44.25.1")
	md := flow.PacketMetadata{IPVersion: 6, Protocol: flow.ProtocolICMPv6, Source: flow.Endpoint{Addr: netip.MustParseAddr("fd42::70"), Port: 1234}, Destination: flow.Endpoint{Addr: netip.MustParseAddr("fc00::1"), Port: 1234}, TrafficClass: flow.ClassMappedSCION}
	snap, _ := d.flowManager.ObserveTx(md, 100, flow.EgressSCION)
	// Register request from local
	d.rememberSCMPInfo(snap.ID, 1, localIA, localHost, 32767, 3)
	// Reply comes from intermediate router, different src host, but same local dst and id/seq
	_, res := d.lookupSCMPInfo(1, localIA, localHost, 32767, 3)
	if res != SCIONLookupHit {
		t.Fatalf("expected HIT for traceroute even with different router src, got %v", res)
	}
}
