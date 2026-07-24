package flow

import (
	"net/netip"
	"time"
)

type Snapshot struct {
	ID ID

	IPVersion uint8
	Protocol  uint8

	EndpointA Endpoint
	EndpointB Endpoint

	LocalEndpoint  Endpoint
	RemoteEndpoint Endpoint
	SCIONDstIP     netip.Addr

	Status     Status
	EgressKind EgressKind
	SrcIA      string
	DstIA      string

	TxPackets uint64
	TxBytes   uint64
	RxPackets uint64
	RxBytes   uint64

	CreatedAt time.Time
	LastSeen  time.Time
}

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
