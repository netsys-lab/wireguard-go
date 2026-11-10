package flow

import (
	"net/netip"
	"time"
)

// Snapshot is an immutable, point-in-time copy of a Flow. It is safe to pass
// around without locking and is converted to a FlowDTO for the frontend.
type Snapshot struct {
	ID ID

	IPVersion uint8
	Protocol  uint8

	EndpointA Endpoint
	EndpointB Endpoint

	LocalEndpoint  Endpoint
	RemoteEndpoint Endpoint
	SCIONDstIP     netip.Addr

	Status       Status
	EgressKind   EgressKind
	TrafficClass TrafficClass
	SrcIA        string
	DstIA        string

	TxPackets uint64
	TxBytes   uint64
	RxPackets uint64
	RxBytes   uint64

	CreatedAt time.Time
	LastSeen  time.Time

	// Socket tuple of the sending app (see Flow.socketLocal and NewFlowEvent).
	// Internal only; not part of FlowDTO.
	SocketProtocol uint8
	SocketLocal    Endpoint
	SocketRemote   Endpoint
}

// ProtocolName returns a human-readable name for the L4 protocol (used in logs).
func (s Snapshot) ProtocolName() string {
	switch s.Protocol {
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	default:
		return "unknown"
	}
}
