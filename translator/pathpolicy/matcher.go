package pathpolicy

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/scionproto/scion/pkg/addr"
)

// PacketInfo describes a packet or flow for matcher evaluation.
type PacketInfo struct {
	SrcIA    addr.IA
	DstIA    addr.IA
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol string // "tcp" or "udp"
	DSCP     uint8  // 6-bit DSCP value (TrafficClass >> 2)
}

// scionAddr is a parsed SCION address with optional wildcard fields.
// Used internally for matcher address comparison.
type scionAddr struct {
	isd     uint16 // 0 = wildcard
	asn     uint64 // 0 = wildcard
	ip      net.IP // nil = wildcard
	port    uint16 // 0 = wildcard
	hasPort bool
}

// parseSCIONAddr parses a SCION address in the format [ISD-ASN,IP]:Port.
// Elements may be replaced with zero from right to left to define wildcards.
//
// Examples:
//   - "[1-ff00:0:1,10.0.0.1]:22"  — full address
//   - "1-ff00:0:1,10.0.0.1"       — no port
//   - "1-ff00:0:1"                — no IP, no port
//   - "1-64512"                   — ISD-ASN (plain ASN)
//   - "1"                         — ISD only
//   - ""                          — wildcard (matches everything)
func parseSCIONAddr(s string) (scionAddr, error) {
	if s == "" {
		return scionAddr{}, nil
	}

	sa := scionAddr{}

	// Check for [addr]:port format.
	if strings.HasPrefix(s, "[") {
		closeBracket := strings.LastIndex(s, "]")
		if closeBracket < 0 {
			return scionAddr{}, fmt.Errorf("missing closing bracket in %q", s)
		}

		inner := s[1:closeBracket]
		rest := s[closeBracket+1:]

		if strings.HasPrefix(rest, ":") {
			portStr := rest[1:]
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				return scionAddr{}, fmt.Errorf("invalid port %q: %w", portStr, err)
			}
			sa.port = uint16(port)
			sa.hasPort = true
		}

		return parseAddrInner(inner, sa)
	}

	// No brackets — could be "ISD-ASN,IP" or "ISD-ASN" or "ISD".
	return parseAddrInner(s, sa)
}

// parseAddrInner parses the "ISD-ASN,IP" part of a SCION address.
func parseAddrInner(s string, sa scionAddr) (scionAddr, error) {
	if s == "" || s == "0" {
		return sa, nil
	}

	// Split on ',' to separate IA from IP.
	commaIdx := strings.Index(s, ",")
	var iaPart, ipPart string
	if commaIdx >= 0 {
		iaPart = s[:commaIdx]
		ipPart = s[commaIdx+1:]
	} else {
		iaPart = s
	}

	// Parse IA part.
	if iaPart != "" && iaPart != "0" {
		ia, err := addr.ParseIA(iaPart)
		if err != nil {
			// Try as plain "ISD" or "ISD-ASN" with numeric ASN.
			if err2 := parseIAFallback(iaPart, &sa); err2 != nil {
				return scionAddr{}, fmt.Errorf("invalid IA %q: %w", iaPart, err)
			}
		} else {
			sa.isd = uint16(ia.ISD())
			sa.asn = uint64(ia.AS())
		}
	}

	// Parse IP part.
	if ipPart != "" && ipPart != "0" {
		ip := net.ParseIP(ipPart)
		if ip == nil {
			return scionAddr{}, fmt.Errorf("invalid IP %q", ipPart)
		}
		sa.ip = ip
	}

	return sa, nil
}

// parseIAFallback handles "ISD" or "ISD-ASN" with numeric ASN.
func parseIAFallback(s string, sa *scionAddr) error {
	dashIdx := strings.Index(s, "-")
	if dashIdx < 0 {
		// Just ISD.
		isd, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return err
		}
		sa.isd = uint16(isd)
		return nil
	}

	isdStr := s[:dashIdx]
	asnStr := s[dashIdx+1:]

	isd, err := strconv.ParseUint(isdStr, 10, 16)
	if err != nil {
		return err
	}
	sa.isd = uint16(isd)

	if asnStr != "0" && asnStr != "" {
		asn, err := strconv.ParseUint(asnStr, 10, 64)
		if err != nil {
			return err
		}
		sa.asn = asn
	}

	return nil
}

// matchesAddr returns true if the parsed address matches the given packet address fields.
func (sa *scionAddr) matchesAddr(ia addr.IA, ip net.IP, port uint16) bool {
	if sa.isd != 0 && uint16(ia.ISD()) != sa.isd {
		return false
	}

	if sa.asn != 0 && uint64(ia.AS()) != sa.asn {
		return false
	}

	if sa.ip != nil && !sa.ip.Equal(ip) {
		return false
	}

	if sa.hasPort && sa.port != 0 && sa.port != port {
		return false
	}

	return true
}

// MatchPacket evaluates the matchers in order against the given packet info
// and returns the name of the first matching policy. If no matcher matches,
// returns "default".
func MatchPacket(matchers []Matcher, info PacketInfo) string {
	for _, m := range matchers {
		if matchesMatcher(m, info) {
			return m.PolicyName
		}
	}
	return "default"
}

// matchesMatcher returns true if all clauses of the matcher match the packet.
func matchesMatcher(m Matcher, info PacketInfo) bool {
	// Destination clause.
	if m.Destination != "" {
		dst, err := parseSCIONAddr(m.Destination)
		if err != nil {
			return false
		}
		if !dst.matchesAddr(info.DstIA, info.DstIP, info.DstPort) {
			return false
		}
	}

	// Source clause.
	if m.Source != "" {
		src, err := parseSCIONAddr(m.Source)
		if err != nil {
			return false
		}
		if !src.matchesAddr(info.SrcIA, info.SrcIP, info.SrcPort) {
			return false
		}
	}

	// Protocol clause.
	if m.Protocol != "" {
		if !strings.EqualFold(m.Protocol, info.Protocol) {
			return false
		}
	}

	// Traffic class clause.
	if m.TrafficClass != nil {
		if *m.TrafficClass != info.DSCP {
			return false
		}
	}

	return true
}
