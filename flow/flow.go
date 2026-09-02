package flow

import (
	"net/netip"
	"sync/atomic"
	"time"
)

// TrafficClass identifies the packet classification for fast-path routing
type TrafficClass uint8

const (
	ClassPlainIP       TrafficClass = 0
	ClassMappedSCION   TrafficClass = 1
	ClassNativeSCION   TrafficClass = 2
	ClassUnclassified  TrafficClass = 255
)

type Flow struct {
	id        ID
	ipVersion uint8
	protocol  uint8
	endpointA Endpoint
	endpointB Endpoint

	localEndpoint  Endpoint
	remoteEndpoint Endpoint
	scionDstIP     netip.Addr

	status        Status
	egressKind    EgressKind
	trafficClass  TrafficClass
	srcIA         string
	dstIA         string
	createdAt     time.Time

	// Atomic counters for lock-free updates
	txPackets atomic.Uint64
	txBytes   atomic.Uint64
	rxPackets atomic.Uint64
	rxBytes   atomic.Uint64

	// Last seen timestamp in nanoseconds for atomic updates
	lastSeenNano atomic.Int64
}

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
	}
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

// getTrafficClass returns the traffic class for this flow
func (f *Flow) getTrafficClass() TrafficClass {
	return f.trafficClass
}
