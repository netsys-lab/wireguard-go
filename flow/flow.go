package flow

import (
	"log"
	"net/netip"
	"sync/atomic"
	"time"
)

// TrafficClass identifies how a flow is carried: plain IP, mapped SCION
// (fc00::/8 IPv6 translated by the translator) or native SCION (app already
// sends SCION/UDP). The values mirror header_parsing.Class* constants.
type TrafficClass uint8

const (
	ClassPlainIP      TrafficClass = 0
	ClassMappedSCION  TrafficClass = 1
	ClassNativeSCION  TrafficClass = 2
	ClassUnclassified TrafficClass = 255
)

// Flow is the mutable, internal state of one tracked connection. Identity fields
// are written once at creation; counters and lastSeen are updated lock-free via
// atomics. Callers outside the package only ever see a Snapshot copy.
type Flow struct {
	id        ID
	ipVersion uint8
	protocol  uint8
	endpointA Endpoint
	endpointB Endpoint

	localEndpoint  Endpoint
	remoteEndpoint Endpoint
	scionDstIP     netip.Addr

	status       Status
	egressKind   EgressKind
	trafficClass TrafficClass
	srcIA        string
	dstIA        string
	createdAt    time.Time

	// Socket tuple as seen by the app on the phone (reported in NewFlowEvent so
	// the Android side can look up the owning app). Equals local/remote for
	// plain IP and mapped SCION; for native SCION it is the outer UDP tuple
	// towards the border router. Immutable after creation.
	socketProtocol uint8
	socketLocal    Endpoint
	socketRemote   Endpoint

	// Atomic counters for lock-free updates
	txPackets atomic.Uint64
	txBytes   atomic.Uint64
	rxPackets atomic.Uint64
	rxBytes   atomic.Uint64

	// Last seen timestamp in nanoseconds for atomic updates
	lastSeenNano atomic.Int64
}

// snapshot returns an immutable copy of the flow, loading all atomic counters.
// It is the only way flow state leaves the Manager.
func (f *Flow) snapshot() Snapshot {
	return Snapshot{
		ID:             f.id,
		IPVersion:      f.ipVersion,
		Protocol:       f.protocol,
		EndpointA:      f.endpointA,
		EndpointB:      f.endpointB,
		LocalEndpoint:  f.localEndpoint,
		RemoteEndpoint: f.remoteEndpoint,
		SCIONDstIP:     f.scionDstIP,
		Status:         f.status,
		EgressKind:     f.egressKind,
		TrafficClass:   f.trafficClass,
		SrcIA:          f.srcIA,
		DstIA:          f.dstIA,
		TxPackets:      f.txPackets.Load(),
		TxBytes:        f.txBytes.Load(),
		RxPackets:      f.rxPackets.Load(),
		RxBytes:        f.rxBytes.Load(),
		CreatedAt:      f.createdAt,
		LastSeen:       time.Unix(0, f.lastSeenNano.Load()),
		SocketProtocol: f.socketProtocol,
		SocketLocal:    f.socketLocal,
		SocketRemote:   f.socketRemote,
	}
}

// initSocket sets the socket tuple of a newly created flow. local/remote are
// the endpoints from the app's point of view. Must be called before the flow
// is published in the Manager maps.
func (f *Flow) initSocket(protocol uint8, local, remote Endpoint) {
	f.socketProtocol = protocol
	f.socketLocal = local
	f.socketRemote = remote
}

// enrichSCIONMetadata copies SCION-specific metadata from a packet into the
// flow when the corresponding flow fields are still empty (first-writer-wins).
// It does not change endpointA/endpointB, localEndpoint/remoteEndpoint,
// counters, or timestamps.
func (f *Flow) enrichSCIONMetadata(metadata PacketMetadata) {
	if f.srcIA == "" && metadata.SrcIA != "" {
		f.srcIA = metadata.SrcIA
	}
	if f.dstIA == "" && metadata.DstIA != "" {
		f.dstIA = metadata.DstIA
	}
	if !f.scionDstIP.IsValid() && metadata.SCIONDstIP.IsValid() {
		f.scionDstIP = metadata.SCIONDstIP
	}
}

// setEgressKind sets the egress kind on creation or promotes unknown -> known.
// It does not silently overwrite a non-unknown kind with a different non-unknown kind.
func (f *Flow) setEgressKind(kind EgressKind) {
	if f.egressKind == EgressUnknown || f.egressKind == "" {
		if kind != EgressUnknown && kind != "" {
			log.Printf("[FLOW-DEBUG] [Flow] Flow id=%d promoted egressKind: '%s' -> '%s'", f.id, f.egressKind, kind)
		}
		f.egressKind = kind
	}
}

// setTrafficClass sets the traffic class (PlainIP, MappedSCION, NativeSCION).
// Only sets on creation; does not overwrite if already set.
func (f *Flow) setTrafficClass(class TrafficClass) {
	if f.trafficClass == ClassUnclassified {
		f.trafficClass = class
	}
}

// getTrafficClass returns the traffic class stored on the flow.
func (f *Flow) getTrafficClass() TrafficClass {
	return f.trafficClass
}
