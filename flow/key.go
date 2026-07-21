package flow

import (
	"net/netip"
)

type Endpoint struct {
	Addr netip.Addr
	Port uint16
}

func (e Endpoint) String() string {
	return netip.AddrPortFrom(e.Addr, e.Port).String()
}

func (e Endpoint) less(other Endpoint) bool {
	if cmp := e.Addr.Compare(other.Addr); cmp != 0 {
		return cmp < 0
	}
	return e.Port < other.Port
}

type Key struct {
	IPVersion uint8
	Protocol  uint8
	endpointA Endpoint
	endpointB Endpoint
}

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
