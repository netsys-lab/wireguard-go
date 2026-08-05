package header_parsing

const DefaultSCIONEndhostPort uint16 = 30041

type DispatchPortRange struct {
	Start uint16
	End   uint16
	Valid bool
}

func (r DispatchPortRange) Contains(port uint16) bool {
	return r.Valid && port >= r.Start && port <= r.End
}

func chooseSameASDispatchPort(
	innerDstPort uint16,
	hasInnerDstPort bool,
	hostPort uint16,
	dispatched DispatchPortRange,
) uint16 {
	// TCP/UDP: use original destination port, e.g. TCP dst 443.
	if hasInnerDstPort && dispatched.Contains(innerDstPort) {
		return innerDstPort
	}

	// ICMP/SCMP has no TCP/UDP destination port, so no inner L4 port is
	// available. Fall back to the translator/endhost control port (hostPort,
	// e.g. 35000) when it falls within the dispatched port range.
	if hostPort != 0 && dispatched.Contains(hostPort) {
		return hostPort
	}

	return DefaultSCIONEndhostPort
}
