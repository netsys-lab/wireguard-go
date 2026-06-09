package pathpolicy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
)

// HopPredicate represents a parsed hop predicate of the form ISD-ASN#Ig,Eg.
// Zero values act as wildcards.
type HopPredicate struct {
	ISD     uint16
	ASN     uint64
	Ingress uint64
	Egress  uint64
	// ifMode is true when the predicate uses the single-IF form (ISD-ASN#IF).
	ifMode bool
}

// ParseHopPredicate parses a hop predicate string.
//
// Accepted formats:
//   - "ISD-ASN#Ig,Eg"  (ingress and egress)
//   - "ISD-ASN#IF"     (single interface, matches either ingress or egress)
//   - "ISD-ASN"        (AS only, no interface constraint)
//   - "ISD"            (ISD only)
//   - "0"              (wildcard: matches everything)
//
// Zero elements may be omitted from right to left.
func ParseHopPredicate(s string) (HopPredicate, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return HopPredicate{}, fmt.Errorf("empty hop predicate")
	}

	hp := HopPredicate{}

	// Split on '#' to separate AS part from interface part.
	parts := strings.SplitN(s, "#", 2)
	asPart := parts[0]

	// Parse AS part: "ISD-ASN" or "ISD" or "0"
	if err := hp.parseAS(asPart); err != nil {
		return HopPredicate{}, fmt.Errorf("hop predicate %q: %w", s, err)
	}

	// Parse interface part if present.
	if len(parts) == 2 {
		ifPart := parts[1]
		if err := hp.parseInterfaces(ifPart); err != nil {
			return HopPredicate{}, fmt.Errorf("hop predicate %q: %w", s, err)
		}
	}

	return hp, nil
}

func (hp *HopPredicate) parseAS(s string) error {
	if s == "" || s == "0" {
		// Wildcard.
		return nil
	}

	// Try to parse as SCION IA (e.g., "1-ff00:0:110" or "1-64512").
	ia, err := addr.ParseIA(s)
	if err == nil {
		hp.ISD = uint16(ia.ISD())
		hp.ASN = uint64(ia.AS())
		return nil
	}

	// Try parsing as just ISD (single number).
	dashIdx := strings.Index(s, "-")
	if dashIdx < 0 {
		isd, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid ISD %q: %w", s, err)
		}
		hp.ISD = uint16(isd)
		return nil
	}

	// ISD-ASN where ASN might be a plain number.
	isdStr := s[:dashIdx]
	asnStr := s[dashIdx+1:]

	isd, err := strconv.ParseUint(isdStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid ISD %q: %w", isdStr, err)
	}
	hp.ISD = uint16(isd)

	if asnStr == "0" || asnStr == "" {
		return nil
	}

	asn, err := strconv.ParseUint(asnStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid ASN %q: %w", asnStr, err)
	}
	hp.ASN = asn

	return nil
}

func (hp *HopPredicate) parseInterfaces(s string) error {
	if s == "" || s == "0" {
		return nil
	}

	// Check for "Ig,Eg" format.
	if strings.Contains(s, ",") {
		parts := strings.SplitN(s, ",", 2)

		if parts[0] != "" && parts[0] != "0" {
			ig, err := strconv.ParseUint(parts[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid ingress %q: %w", parts[0], err)
			}
			hp.Ingress = ig
		}

		if parts[1] != "" && parts[1] != "0" {
			eg, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid egress %q: %w", parts[1], err)
			}
			hp.Egress = eg
		}

		return nil
	}

	// Single IF form: matches either ingress or egress.
	ifID, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid interface %q: %w", s, err)
	}
	hp.Ingress = ifID
	hp.Egress = ifID
	hp.ifMode = true

	return nil
}

// MatchInterface returns true if the hop predicate matches the given path interface.
func (hp *HopPredicate) MatchInterface(pi snet.PathInterface) bool {
	// ISD check (0 = wildcard).
	if hp.ISD != 0 && uint16(pi.IA.ISD()) != hp.ISD {
		return false
	}

	// ASN check (0 = wildcard).
	if hp.ASN != 0 && uint64(pi.IA.AS()) != hp.ASN {
		return false
	}

	// Interface check.
	if hp.ifMode {
		// Single IF form: must match either.
		if hp.Ingress != 0 && uint64(pi.ID) != hp.Ingress {
			return false
		}
	} else {
		// For the Ig,Eg form with specific interface IDs, we check the
		// interface ID against both. The interface list from path metadata
		// contains alternating ingress/egress entries, so a single PathInterface
		// can represent either role. We match if the ID equals either the
		// required ingress or egress (non-zero means must match).
		if hp.Ingress != 0 && hp.Egress != 0 {
			// Both specified: check if the interface ID matches either.
			if uint64(pi.ID) != hp.Ingress && uint64(pi.ID) != hp.Egress {
				return false
			}
		} else if hp.Ingress != 0 {
			if uint64(pi.ID) != hp.Ingress {
				return false
			}
		} else if hp.Egress != 0 {
			if uint64(pi.ID) != hp.Egress {
				return false
			}
		}
	}

	return true
}

// MatchHop returns true if the hop predicate matches a hop defined by
// an ingress and egress interface pair (as they appear pairwise in path metadata).
func (hp *HopPredicate) MatchHop(ingress, egress snet.PathInterface) bool {
	// ISD check: must match the AS of the hop (both interfaces should be in same AS for internal hops,
	// or we check the relevant one).
	if hp.ISD != 0 {
		if uint16(ingress.IA.ISD()) != hp.ISD && uint16(egress.IA.ISD()) != hp.ISD {
			return false
		}
	}

	if hp.ASN != 0 {
		if uint64(ingress.IA.AS()) != hp.ASN && uint64(egress.IA.AS()) != hp.ASN {
			return false
		}
	}

	if hp.ifMode {
		// Single IF: matches if either interface ID equals the specified IF.
		if hp.Ingress != 0 {
			if uint64(ingress.ID) != hp.Ingress && uint64(egress.ID) != hp.Ingress {
				return false
			}
		}
	} else {
		if hp.Ingress != 0 && uint64(ingress.ID) != hp.Ingress {
			return false
		}
		if hp.Egress != 0 && uint64(egress.ID) != hp.Egress {
			return false
		}
	}

	return true
}

// IsWildcard returns true if the hop predicate matches any hop.
func (hp *HopPredicate) IsWildcard() bool {
	return hp.ISD == 0 && hp.ASN == 0 && hp.Ingress == 0 && hp.Egress == 0
}

// String returns a human-readable representation of the hop predicate.
func (hp HopPredicate) String() string {
	var ia string
	if hp.ISD == 0 && hp.ASN == 0 {
		ia = "0"
	} else if hp.ASN == 0 {
		ia = fmt.Sprintf("%d", hp.ISD)
	} else {
		a, _ := addr.IAFrom(addr.ISD(hp.ISD), addr.AS(hp.ASN))
		ia = a.String()
	}

	if hp.Ingress == 0 && hp.Egress == 0 {
		return ia
	}

	if hp.ifMode {
		return fmt.Sprintf("%s#%d", ia, hp.Ingress)
	}

	return fmt.Sprintf("%s#%d,%d", ia, hp.Ingress, hp.Egress)
}

// hopInterfaces extracts the interface list from path metadata, returning
// pairs of (ingress, egress) for each hop along the path.
func hopInterfaces(ifaces []snet.PathInterface) []snet.PathInterface {
	return ifaces
}

// interfaceToIface converts a PathInterface to an iface.ID (for reference).
func interfaceToIface(pi snet.PathInterface) iface.ID {
	return pi.ID
}
