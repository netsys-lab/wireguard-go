package flow

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func evEndpoint(addr string, port uint16) Endpoint {
	return Endpoint{Addr: netip.MustParseAddr(addr), Port: port}
}

func evMetadata(proto uint8, src, dst Endpoint) PacketMetadata {
	return PacketMetadata{IPVersion: 4, Protocol: proto, Source: src, Destination: dst}
}

func TestObserveTxSocketTupleDefaultsToPacketTuple(t *testing.T) {
	m := NewManager()
	src := evEndpoint("10.0.0.2", 40000)
	dst := evEndpoint("1.1.1.1", 443)
	snap, _ := m.ObserveTx(evMetadata(ProtocolTCP, src, dst), 60, EgressIP)

	if snap.SocketProtocol != ProtocolTCP || snap.SocketLocal != src || snap.SocketRemote != dst {
		t.Fatalf("unexpected socket tuple: proto=%d local=%v remote=%v", snap.SocketProtocol, snap.SocketLocal, snap.SocketRemote)
	}
}

func TestObserveTxUsesExplicitSocketTuple(t *testing.T) {
	m := NewManager()
	md := evMetadata(ProtocolTCP, evEndpoint("10.0.8.2", 5000), evEndpoint("10.0.0.5", 443))
	md.SocketProtocol = ProtocolUDP
	md.SocketSource = evEndpoint("10.0.0.2", 31000)
	md.SocketDestination = evEndpoint("192.168.1.1", 30041)

	snap, _ := m.ObserveTx(md, 100, EgressSCION)
	if snap.SocketProtocol != ProtocolUDP {
		t.Fatalf("socket protocol = %d, want UDP", snap.SocketProtocol)
	}
	if snap.SocketLocal != md.SocketSource || snap.SocketRemote != md.SocketDestination {
		t.Fatalf("socket tuple not taken from metadata: %v -> %v", snap.SocketLocal, snap.SocketRemote)
	}
	if snap.LocalEndpoint != md.Source {
		t.Fatalf("flow endpoints must stay the packet tuple, got local=%v", snap.LocalEndpoint)
	}
}

func TestObserveRxSocketTupleIsSwapped(t *testing.T) {
	m := NewManager()
	remote := evEndpoint("1.1.1.1", 443)
	local := evEndpoint("10.0.0.2", 40000)
	// Incoming packet: source is the remote side.
	snap, _ := m.ObserveRx(evMetadata(ProtocolUDP, remote, local), 60, EgressIP)

	if snap.SocketLocal != local || snap.SocketRemote != remote {
		t.Fatalf("rx socket tuple not swapped: local=%v remote=%v", snap.SocketLocal, snap.SocketRemote)
	}
}

func TestOnFlowCreatedCalledOncePerNewFlow(t *testing.T) {
	m := NewManager()
	var mu sync.Mutex
	var created []ID
	m.SetOnFlowCreated(func(s Snapshot) {
		mu.Lock()
		created = append(created, s.ID)
		mu.Unlock()
	})

	a := evMetadata(ProtocolTCP, evEndpoint("10.0.0.2", 40000), evEndpoint("1.1.1.1", 443))
	b := evMetadata(ProtocolTCP, evEndpoint("10.0.0.2", 40001), evEndpoint("1.1.1.1", 443))
	m.ObserveTx(a, 60, EgressIP)
	m.ObserveTx(a, 60, EgressIP) // existing flow: no callback
	m.ObserveRx(evMetadata(ProtocolTCP, a.Destination, a.Source), 60, EgressIP)
	m.ObserveTx(b, 60, EgressIP)

	mu.Lock()
	defer mu.Unlock()
	if len(created) != 2 || created[0] != 1 || created[1] != 2 {
		t.Fatalf("callback calls = %v, want [1 2]", created)
	}
}

func TestOnFlowCreatedRunsWithoutManagerLock(t *testing.T) {
	m := NewManager()
	done := make(chan struct{})
	m.SetOnFlowCreated(func(s Snapshot) {
		// Would deadlock if the callback ran while m.mu is held.
		if _, ok := m.GetByID(s.ID); !ok {
			t.Errorf("flow %d not visible in callback", s.ID)
		}
		close(done)
	})
	m.ObserveTx(evMetadata(ProtocolUDP, evEndpoint("10.0.0.2", 5353), evEndpoint("8.8.8.8", 53)), 60, EgressIP)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("callback did not run (deadlock?)")
	}
}

func TestNewFlowEventFromSnapshot(t *testing.T) {
	m := NewManager()
	tcp, _ := m.ObserveTx(evMetadata(ProtocolTCP, evEndpoint("10.0.0.2", 40000), evEndpoint("1.1.1.1", 443)), 60, EgressIP)
	ev, ok := NewFlowEventFromSnapshot(tcp)
	if !ok {
		t.Fatal("expected event for TCP flow")
	}
	want := NewFlowEvent{FlowID: uint64(tcp.ID), Protocol: ProtocolTCP, LocalIP: "10.0.0.2", LocalPort: 40000, RemoteIP: "1.1.1.1", RemotePort: 443}
	if ev != want {
		t.Fatalf("event = %+v, want %+v", ev, want)
	}

	icmp := Snapshot{SocketProtocol: ProtocolICMPv6, SocketLocal: evEndpoint("fd00::2", 1), SocketRemote: evEndpoint("fd00::1", 1)}
	if _, ok := NewFlowEventFromSnapshot(icmp); ok {
		t.Fatal("ICMPv6 must not produce an event")
	}
	if _, ok := NewFlowEventFromSnapshot(Snapshot{SocketProtocol: ProtocolUDP}); ok {
		t.Fatal("invalid addresses must not produce an event")
	}
}

func TestEventQueueDropsWhenFull(t *testing.T) {
	q := NewEventQueue(2)
	for i := 1; i <= 3; i++ {
		ok := q.TryPush(NewFlowEvent{FlowID: uint64(i)})
		if i <= 2 && !ok {
			t.Fatalf("push %d failed", i)
		}
		if i == 3 && ok {
			t.Fatal("push into full queue must fail")
		}
	}
	events, dropped := q.Wait(time.Second, 10, nil)
	if len(events) != 2 || dropped != 1 {
		t.Fatalf("got %d events, dropped=%d; want 2, 1", len(events), dropped)
	}
	if _, dropped = q.Wait(10*time.Millisecond, 10, nil); dropped != 0 {
		t.Fatalf("drop counter not reset, got %d", dropped)
	}
}

func TestEventQueueWaitTimeout(t *testing.T) {
	q := NewEventQueue(4)
	start := time.Now()
	events, _ := q.Wait(30*time.Millisecond, 10, nil)
	if events == nil || len(events) != 0 {
		t.Fatalf("expected empty non-nil slice, got %v", events)
	}
	if time.Since(start) < 25*time.Millisecond {
		t.Fatal("Wait returned before the timeout")
	}
}

func TestEventQueueWaitDone(t *testing.T) {
	q := NewEventQueue(4)
	done := make(chan struct{})
	close(done)
	start := time.Now()
	events, _ := q.Wait(5*time.Second, 10, done)
	if len(events) != 0 || time.Since(start) > time.Second {
		t.Fatal("Wait must return immediately when done is closed")
	}
}

func TestEventQueueWaitMax(t *testing.T) {
	q := NewEventQueue(10)
	for i := 0; i < 5; i++ {
		q.TryPush(NewFlowEvent{FlowID: uint64(i)})
	}
	events, _ := q.Wait(time.Second, 3, nil)
	if len(events) != 3 || q.Len() != 2 {
		t.Fatalf("got %d events, %d left; want 3, 2", len(events), q.Len())
	}
	q.Drain()
	if q.Len() != 0 {
		t.Fatal("Drain must empty the queue")
	}
}

func TestEventQueueWakesUpOnPush(t *testing.T) {
	q := NewEventQueue(4)
	go func() {
		time.Sleep(20 * time.Millisecond)
		q.TryPush(NewFlowEvent{FlowID: 7})
	}()
	events, _ := q.Wait(5*time.Second, 10, nil)
	if len(events) != 1 || events[0].FlowID != 7 {
		t.Fatalf("got %v", events)
	}
}
