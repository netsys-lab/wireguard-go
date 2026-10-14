package header_parsing

// DefaultSCIONEndhostPort is the well-known SCION UDP underlay default port.
// Routers forward SCMP informational requests and any traffic that cannot be
// dispatched by L4 port to this port on the destination end host, and the
// SCMP daemon / dispatcher listens on it. See the SCION "router port
// dispatch" design and underlay protocol docs.
const DefaultSCIONEndhostPort uint16 = 30041

type DispatchPortRange struct {
	Start uint16
	End   uint16
	Valid bool
}

func (r DispatchPortRange) Contains(port uint16) bool {
	return r.Valid && port >= r.Start && port <= r.End
}

// chooseSameASDispatchPort selects the outer UDP destination port for
// same-AS (empty-path) traffic that is delivered directly to the destination
// host instead of via a border router.
//
//   - TCP/UDP data flows carry a real L4 destination port, so the outer UDP
//     destination port is that inner L4 port. The remote application's
//     dispatcherless underlay socket is bound to it, so no range gating or
//     fallback is applied.
//   - SCMP/ICMPv6 has no TCP/UDP destination port. Requests are routed to the
//     well-known SCION end-host port (DefaultSCIONEndhostPort) where the
//     remote SCMP daemon / dispatcher listens.
func chooseSameASDispatchPort(innerDstPort uint16, hasInnerDstPort bool) uint16 {
	// TCP/UDP: use the original destination port, e.g. TCP dst 443.
	if hasInnerDstPort {
		return innerDstPort
	}

	// ICMP/SCMP has no TCP/UDP destination port: use the dispatcher/end-host
	// port so the SCMP request reaches the remote end host.
	return DefaultSCIONEndhostPort
}
