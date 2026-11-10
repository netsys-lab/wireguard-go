package device

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/flow"
)

// newFlowEventsTestDevice builds the minimal Device needed for the new-flow
// event path (flow manager, event queue, closed channel).
func newFlowEventsTestDevice() *Device {
	d := &Device{closed: make(chan struct{})}
	d.flowManager = flow.NewManager()
	d.initFlowEvents()
	return d
}

func tcpMetadata(srcPort uint16) flow.PacketMetadata {
	return flow.PacketMetadata{
		IPVersion:   4,
		Protocol:    flow.ProtocolTCP,
		Source:      flow.Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: srcPort},
		Destination: flow.Endpoint{Addr: netip.MustParseAddr("1.1.1.1"), Port: 443},
	}
}

func TestNewFlowEventsDisabledByDefault(t *testing.T) {
	d := newFlowEventsTestDevice()
	d.flowManager.ObserveTx(tcpMetadata(40000), 60, flow.EgressIP)

	events, _ := d.WaitNewFlowEvents(20*time.Millisecond, 10)
	if len(events) != 0 {
		t.Fatalf("events must be off by default, got %v", events)
	}
}

func TestNewFlowEventsEnabled(t *testing.T) {
	d := newFlowEventsTestDevice()
	d.SetNewFlowEventsEnabled(true)
	snap, _ := d.flowManager.ObserveTx(tcpMetadata(40000), 60, flow.EgressIP)

	events, dropped := d.WaitNewFlowEvents(time.Second, 10)
	if len(events) != 1 || events[0].FlowID != uint64(snap.ID) || dropped != 0 {
		t.Fatalf("got events=%v dropped=%d", events, dropped)
	}
	if events[0].LocalPort != 40000 || events[0].RemoteIP != "1.1.1.1" {
		t.Fatalf("unexpected event %+v", events[0])
	}
}

func TestNewFlowEventsDisableDrainsQueue(t *testing.T) {
	d := newFlowEventsTestDevice()
	d.SetNewFlowEventsEnabled(true)
	d.flowManager.ObserveTx(tcpMetadata(40000), 60, flow.EgressIP)
	d.flowManager.ObserveTx(tcpMetadata(40001), 60, flow.EgressIP)
	d.SetNewFlowEventsEnabled(false)

	if d.NewFlowEventsEnabled() {
		t.Fatal("events still enabled")
	}
	events, _ := d.WaitNewFlowEvents(20*time.Millisecond, 10)
	if len(events) != 0 {
		t.Fatalf("queue not drained, got %v", events)
	}
}

func TestWaitNewFlowEventsReturnsWhenDeviceClosed(t *testing.T) {
	d := newFlowEventsTestDevice()
	close(d.closed)
	start := time.Now()
	d.WaitNewFlowEvents(5*time.Second, 10)
	if time.Since(start) > time.Second {
		t.Fatal("WaitNewFlowEvents must return when the device is closed")
	}
}

// buildIPv4UDP returns a minimal IPv4/UDP packet with the given payload.
func buildIPv4UDP(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	pkt := make([]byte, 20+8+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = flow.ProtocolUDP
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+len(payload)))
	copy(pkt[28:], payload)
	return pkt
}

func TestWithOuterSocketTuple(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.2")
	br := netip.MustParseAddr("192.168.1.1")
	pkt := buildIPv4UDP(src, br, 31000, 30041, []byte{0x00, 0x00, 0x00, 0x01})

	md := flow.PacketMetadata{
		IPVersion:   4,
		Protocol:    flow.ProtocolTCP,
		Source:      flow.Endpoint{Addr: netip.MustParseAddr("10.0.8.2"), Port: 5000},
		Destination: flow.Endpoint{Addr: netip.MustParseAddr("10.0.0.5"), Port: 443},
	}
	got := withOuterSocketTuple(md, pkt)
	if got.SocketProtocol != flow.ProtocolUDP {
		t.Fatalf("socket protocol = %d, want UDP", got.SocketProtocol)
	}
	if got.SocketSource != (flow.Endpoint{Addr: src, Port: 31000}) || got.SocketDestination != (flow.Endpoint{Addr: br, Port: 30041}) {
		t.Fatalf("unexpected socket tuple %v -> %v", got.SocketSource, got.SocketDestination)
	}
	if got.Source != md.Source || got.Protocol != flow.ProtocolTCP {
		t.Fatal("packet tuple must stay unchanged")
	}

	// Unparseable packet: metadata unchanged.
	if unchanged := withOuterSocketTuple(md, []byte{0x45}); unchanged.SocketProtocol != 0 {
		t.Fatal("socket tuple must not be set for an unparseable packet")
	}
}
