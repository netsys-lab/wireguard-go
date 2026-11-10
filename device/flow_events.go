package device

import (
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/flow"
	"golang.zx2c4.com/wireguard/scionlog"
)

// New-flow events (app attribution on Android)
//
// Android can map a socket tuple to the owning app, but only while the socket
// still exists. The backend therefore reports every new TCP/UDP flow right
// when it is created. GoBackend.java runs a thread that blocks in
// WaitNewFlowEvents, looks up the owner and keeps the result on the Android
// side. The backend does not store any owner information.
//
// Events are disabled by default, so the standalone CLI and Android versions
// without the lookup API are not affected.

// flowEventState is embedded into Device.
type flowEventState struct {
	enabled atomic.Bool
	queue   *flow.EventQueue
}

// initFlowEvents creates the event queue and hooks it into the flow manager.
// Called once from NewDevice.
func (device *Device) initFlowEvents() {
	device.flowEvents.queue = flow.NewEventQueue(flow.DefaultEventQueueSize)
	device.flowManager.SetOnFlowCreated(device.publishNewFlowEvent)
}

// SetNewFlowEventsEnabled switches the reporting of new flows on or off.
// Switching off discards all undelivered events.
func (device *Device) SetNewFlowEventsEnabled(enabled bool) {
	device.flowEvents.enabled.Store(enabled)
	if !enabled && device.flowEvents.queue != nil {
		device.flowEvents.queue.Drain()
	}
	if device.scionLog != nil {
		device.scionLog.Infof(scionlog.ComponentFlow, "[FLOW-EVENT] new-flow events enabled=%v", enabled)
	}
}

// NewFlowEventsEnabled reports whether new flows are currently reported.
func (device *Device) NewFlowEventsEnabled() bool {
	return device.flowEvents.enabled.Load()
}

// publishNewFlowEvent is the flow manager's creation callback. It runs on the
// packet path, after the manager lock was released, and never blocks.
func (device *Device) publishNewFlowEvent(s flow.Snapshot) {
	if !device.flowEvents.enabled.Load() || device.flowEvents.queue == nil {
		return
	}
	ev, ok := flow.NewFlowEventFromSnapshot(s)
	if !ok {
		return
	}
	if !device.flowEvents.queue.TryPush(ev) && device.scionLog != nil {
		device.scionLog.Debugf(scionlog.ComponentFlow, "[FLOW-EVENT] queue full, dropped event for flow=%d", s.ID)
	}
}

// WaitNewFlowEvents blocks until new-flow events are available, the timeout
// expires or the device is closed, and returns up to max events plus the
// number of events dropped since the previous call. Called in a loop by the
// Android consumer thread (wgWaitNewFlows).
func (device *Device) WaitNewFlowEvents(timeout time.Duration, max int) ([]flow.NewFlowEvent, uint64) {
	if device.flowEvents.queue == nil {
		return []flow.NewFlowEvent{}, 0
	}
	return device.flowEvents.queue.Wait(timeout, max, device.closed)
}

// withOuterSocketTuple records the outer IP/UDP tuple of a native SCION packet
// as the socket tuple of the flow. For native SCION the flow endpoints come
// from the SCION header, but the app's socket is the outer UDP socket towards
// the border router, which is what the owner lookup needs.
func withOuterSocketTuple(md flow.PacketMetadata, pkt []byte) flow.PacketMetadata {
	outer, err := flow.ParsePacketMetadata(pkt)
	if err != nil {
		return md
	}
	md.SocketProtocol = outer.Protocol
	md.SocketSource = outer.Source
	md.SocketDestination = outer.Destination
	return md
}
