package flow

import (
	"sync/atomic"
	"time"
)

// New-flow events
//
// The backend cannot know which app sent a packet. On Android the owning app
// of a socket can be looked up (ConnectivityManager.getConnectionOwnerUid),
// but only while the socket still exists. Therefore the backend reports every
// new TCP/UDP flow immediately as a NewFlowEvent; the Android side resolves and
// stores the owner itself. The backend does not keep any owner information.

// NewFlowEvent announces a newly created flow together with the socket tuple of
// the sending app. Local/Remote describe the socket as the app on the phone
// sees it: the inner tuple for plain IP and mapped SCION, the outer UDP tuple
// for native SCION (the app's UDP socket towards the border router).
type NewFlowEvent struct {
	FlowID     uint64 `json:"flowId"`
	Protocol   uint8  `json:"protocol"`
	LocalIP    string `json:"localIP"`
	LocalPort  uint16 `json:"localPort"`
	RemoteIP   string `json:"remoteIP"`
	RemotePort uint16 `json:"remotePort"`
}

// NewFlowEventFromSnapshot builds the event for a flow snapshot. ok is false
// if the flow has no socket that could be looked up (only TCP and UDP sockets
// with valid addresses qualify; ICMP/ICMPv6 and mapped SCMP do not).
func NewFlowEventFromSnapshot(s Snapshot) (NewFlowEvent, bool) {
	if s.SocketProtocol != ProtocolTCP && s.SocketProtocol != ProtocolUDP {
		return NewFlowEvent{}, false
	}
	if !s.SocketLocal.Addr.IsValid() || !s.SocketRemote.Addr.IsValid() {
		return NewFlowEvent{}, false
	}
	return NewFlowEvent{
		FlowID:     uint64(s.ID),
		Protocol:   s.SocketProtocol,
		LocalIP:    s.SocketLocal.Addr.String(),
		LocalPort:  s.SocketLocal.Port,
		RemoteIP:   s.SocketRemote.Addr.String(),
		RemotePort: s.SocketRemote.Port,
	}, true
}

// DefaultEventQueueSize bounds the number of undelivered new-flow events.
const DefaultEventQueueSize = 1024

// EventQueue is a bounded queue of new-flow events between the packet path
// (producer, must never block) and the Android consumer thread (blocks in Wait).
// Events that do not fit are dropped and counted.
type EventQueue struct {
	ch      chan NewFlowEvent
	dropped atomic.Uint64
}

// NewEventQueue creates a queue that holds at most size events
// (DefaultEventQueueSize if size <= 0).
func NewEventQueue(size int) *EventQueue {
	if size <= 0 {
		size = DefaultEventQueueSize
	}
	return &EventQueue{ch: make(chan NewFlowEvent, size)}
}

// TryPush enqueues an event without blocking. If the queue is full, the event
// is dropped, the drop counter is incremented and false is returned.
func (q *EventQueue) TryPush(e NewFlowEvent) bool {
	select {
	case q.ch <- e:
		return true
	default:
		q.dropped.Add(1)
		return false
	}
}

// Wait blocks until at least one event is available, the timeout expires or
// done is closed, and then returns up to max events without blocking further.
// It also returns (and resets) the number of events dropped since the last call.
// The returned slice is never nil.
func (q *EventQueue) Wait(timeout time.Duration, max int, done <-chan struct{}) ([]NewFlowEvent, uint64) {
	if max <= 0 {
		max = 256
	}
	events := make([]NewFlowEvent, 0, 8)
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case e := <-q.ch:
		events = append(events, e)
	case <-timer.C:
		return events, q.dropped.Swap(0)
	case <-done:
		return events, q.dropped.Swap(0)
	}
	for len(events) < max {
		select {
		case e := <-q.ch:
			events = append(events, e)
		default:
			return events, q.dropped.Swap(0)
		}
	}
	return events, q.dropped.Swap(0)
}

// Drain discards all queued events (used when events are switched off).
func (q *EventQueue) Drain() {
	for {
		select {
		case <-q.ch:
		default:
			return
		}
	}
}

// Len returns the number of queued events.
func (q *EventQueue) Len() int {
	return len(q.ch)
}
