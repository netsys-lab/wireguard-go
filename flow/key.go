package flow

import (
	"net/netip"
)

// Endpoint is one side of a flow: an IP address plus an L4 port (or the
// ICMPv6/SCMP echo identifier for ICMP-like flows).
type Endpoint struct {
	Addr netip.Addr
	Port uint16
}

// String renders the endpoint as "addr:port" ("[addr]:port" for IPv6).
func (e Endpoint) String() string {
	return netip.AddrPortFrom(e.Addr, e.Port).String()
}

// less defines a total order on endpoints (address first, then port).
// It is used by newKey to put both endpoints into a canonical order.
func (e Endpoint) less(other Endpoint) bool {
	if cmp := e.Addr.Compare(other.Addr); cmp != 0 {
		return cmp < 0
	}
	return e.Port < other.Port
}

// Key is the map key used by Manager.flowsByKey. It is a canonical 5-tuple:
// IP version, protocol and the two endpoints in sorted order. Because the order
// is canonical, A->B and B->A map to the same Key, so request and reply packets
// land in the same flow. Note: the Key contains no SCION ISD-AS.
type Key struct {
	IPVersion uint8
	Protocol  uint8
	endpointA Endpoint
	endpointB Endpoint
}

// newKey builds the canonical Key for a packet: the smaller endpoint (see less)
// becomes endpointA, the larger one endpointB. Direction is intentionally lost.
func newKey(ipVersion, protocol uint8, src, dst Endpoint) Key {
	if src.less(dst) {
		return Key{
			IPVersion: ipVersion,
			Protocol:  protocol,
			endpointA: src,
			endpointB: dst,
		}
	}
	return Key{
		IPVersion: ipVersion,
		Protocol:  protocol,
		endpointA: dst,
		endpointB: src,
	}
}
