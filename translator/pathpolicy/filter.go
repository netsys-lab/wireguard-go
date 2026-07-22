package pathpolicy

import (
	"log"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/snet"

	pathpool "golang.zx2c4.com/wireguard/translator/pathpool"
)

// FilterPaths applies the ACL, sequence, and requirements rules of a resolved
// policy to a set of cached paths, returning only paths that pass all filters.
func FilterPaths(policy *ResolvedPolicy, paths []pathpool.CachedPath) []pathpool.CachedPath {
	if policy == nil {
		return paths
	}

	result := paths

	// Apply ACL filter.
	if len(policy.ACL) > 0 {
		result = filterACL(policy.ACL, result)
	}

	// Apply sequence filter.
	if policy.Sequence != "" {
		result = filterSequence(policy.Sequence, result)
	}

	// Apply requirements filter.
	if policy.Requirements != nil {
		result = filterRequirements(policy.Requirements, result)
	}

	return result
}

// --- ACL Filtering ---

// aclRule represents a parsed ACL entry: an allow/deny flag and a hop predicate.
type aclRule struct {
	allow     bool
	predicate HopPredicate
}

// parseACL parses the ACL rule list from policy strings.
// Each entry is "+ HopPredicate" or "- HopPredicate" or just "+" or "-".
func parseACL(rules []string) []aclRule {
	parsed := make([]aclRule, 0, len(rules))

	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		var allow bool
		var predStr string

		if strings.HasPrefix(rule, "+") {
			allow = true
			predStr = strings.TrimSpace(rule[1:])
		} else if strings.HasPrefix(rule, "-") {
			allow = false
			predStr = strings.TrimSpace(rule[1:])
		} else {
			log.Printf("[PATHPOLICY] invalid ACL rule (no +/-): %q", rule)
			continue
		}

		if predStr == "" {
			// Bare "+" or "-": matches everything.
			parsed = append(parsed, aclRule{
				allow:     allow,
				predicate: HopPredicate{}, // wildcard
			})
			continue
		}

		hp, err := ParseHopPredicate(predStr)
		if err != nil {
			log.Printf("[PATHPOLICY] invalid ACL hop predicate %q: %v", predStr, err)
			continue
		}

		parsed = append(parsed, aclRule{allow: allow, predicate: hp})
	}

	return parsed
}

// filterACL applies ACL rules to paths.
// For each hop on each path, the ACL rules are checked in order (first-match-wins).
// A path is allowed only if all of its hops are allowed.
func filterACL(aclRules []string, paths []pathpool.CachedPath) []pathpool.CachedPath {
	rules := parseACL(aclRules)
	if len(rules) == 0 {
		return paths
	}

	var result []pathpool.CachedPath
	for _, p := range paths {
		if pathPassesACL(rules, p) {
			result = append(result, p)
		}
	}
	return result
}

// pathPassesACL returns true if every interface on the path is allowed by the ACL.
func pathPassesACL(rules []aclRule, p pathpool.CachedPath) bool {
	meta := p.Path.Metadata()
	if meta == nil || len(meta.Interfaces) == 0 {
		// No metadata: ACL can't evaluate, so allow by default.
		return true
	}

	for _, iface := range meta.Interfaces {
		allowed := evaluateACLForInterface(rules, iface)
		if !allowed {
			return false
		}
	}
	return true
}

// evaluateACLForInterface checks a single interface against ACL rules.
// Returns true if the interface is allowed, false if denied.
// If no rule matches, the default is deny (implicit deny-all at the end).
func evaluateACLForInterface(rules []aclRule, iface snet.PathInterface) bool {
	for _, rule := range rules {
		if rule.predicate.MatchInterface(iface) {
			return rule.allow
		}
	}
	// No rule matched: default deny.
	return false
}

// --- Sequence Filtering ---

// filterSequence applies a sequence filter to paths.
// The sequence is a space-separated list of hop predicate tokens with optional
// regex quantifiers (*, +, ?). The sequence must match the entire path interface list.
func filterSequence(sequence string, paths []pathpool.CachedPath) []pathpool.CachedPath {
	tokens, err := parseSequence(sequence)
	if err != nil {
		log.Printf("[PATHPOLICY] invalid sequence %q: %v", sequence, err)
		return paths
	}

	var result []pathpool.CachedPath
	for _, p := range paths {
		if pathMatchesSequence(tokens, p) {
			result = append(result, p)
		}
	}
	return result
}

// seqToken is a token in a sequence expression.
type seqToken struct {
	predicate HopPredicate
	quantifier rune // 0 = exact once, '*' = zero or more, '+' = one or more, '?' = zero or one
}

// parseSequence parses a sequence string into tokens.
// Format: "HopPred1 HopPred2* HopPred3?"
func parseSequence(seq string) ([]seqToken, error) {
	parts := strings.Fields(seq)
	tokens := make([]seqToken, 0, len(parts))

	for _, part := range parts {
		var quantifier rune
		predStr := part

		// Check for trailing quantifier.
		if len(part) > 0 {
			last := rune(part[len(part)-1])
			if last == '*' || last == '+' || last == '?' {
				quantifier = last
				predStr = part[:len(part)-1]
			}
		}

		hp, err := ParseHopPredicate(predStr)
		if err != nil {
			return nil, err
		}

		tokens = append(tokens, seqToken{
			predicate:  hp,
			quantifier: quantifier,
		})
	}

	return tokens, nil
}

// pathMatchesSequence returns true if the path's interface list matches the sequence.
// Uses recursive backtracking to handle quantifiers.
func pathMatchesSequence(tokens []seqToken, p pathpool.CachedPath) bool {
	meta := p.Path.Metadata()
	if meta == nil {
		// No metadata: can't evaluate sequence; allow by default.
		return true
	}

	ifaces := meta.Interfaces
	return matchSequenceRecursive(tokens, 0, ifaces, 0)
}

// matchSequenceRecursive attempts to match tokens[ti:] against ifaces[ii:].
func matchSequenceRecursive(tokens []seqToken, ti int, ifaces []snet.PathInterface, ii int) bool {
	// Both exhausted: match.
	if ti == len(tokens) {
		return ii == len(ifaces)
	}

	tok := tokens[ti]

	switch tok.quantifier {
	case '*': // zero or more
		// Try consuming 0, 1, 2, ... interfaces.
		for k := 0; k <= len(ifaces)-ii; k++ {
			if allMatch(tok.predicate, ifaces[ii:ii+k]) {
				if matchSequenceRecursive(tokens, ti+1, ifaces, ii+k) {
					return true
				}
			} else {
				break // Once a non-match, further extensions won't match either.
			}
		}
		return false

	case '+': // one or more
		for k := 1; k <= len(ifaces)-ii; k++ {
			if allMatch(tok.predicate, ifaces[ii:ii+k]) {
				if matchSequenceRecursive(tokens, ti+1, ifaces, ii+k) {
					return true
				}
			} else {
				break
			}
		}
		return false

	case '?': // zero or one
		// Try zero.
		if matchSequenceRecursive(tokens, ti+1, ifaces, ii) {
			return true
		}
		// Try one.
		if ii < len(ifaces) && tok.predicate.MatchInterface(ifaces[ii]) {
			return matchSequenceRecursive(tokens, ti+1, ifaces, ii+1)
		}
		return false

	default: // exact once
		if ii >= len(ifaces) {
			return false
		}
		if !tok.predicate.MatchInterface(ifaces[ii]) {
			return false
		}
		return matchSequenceRecursive(tokens, ti+1, ifaces, ii+1)
	}
}

// allMatch returns true if the predicate matches all given interfaces.
func allMatch(hp HopPredicate, ifaces []snet.PathInterface) bool {
	for _, iface := range ifaces {
		if !hp.MatchInterface(iface) {
			return false
		}
	}
	return true
}

// --- Requirements Filtering ---

// filterRequirements applies metadata requirements to paths.
func filterRequirements(req *Requirements, paths []pathpool.CachedPath) []pathpool.CachedPath {
	if req == nil {
		return paths
	}

	var result []pathpool.CachedPath
	for _, p := range paths {
		if pathMeetsRequirements(req, p) {
			result = append(result, p)
		}
	}
	return result
}

// pathMeetsRequirements checks if a path's metadata satisfies the requirements.
func pathMeetsRequirements(req *Requirements, p pathpool.CachedPath) bool {
	meta := p.Path.Metadata()
	if meta == nil {
		// No metadata: can't verify requirements. Be conservative and allow.
		return true
	}

	// min_mtu check.
	if req.MinMTU != 0 && meta.MTU < req.MinMTU {
		return false
	}

	// max_meta_lat check: total latency in milliseconds.
	if req.MaxMetaLat != 0 {
		totalLat := totalLatency(meta.Latency)
		if totalLat >= 0 {
			latMs := uint64(totalLat.Milliseconds())
			if latMs > req.MaxMetaLat {
				return false
			}
		}
	}

	// min_meta_bw check: minimum bandwidth in kbit/s.
	if req.MinMetaBW != 0 {
		minBW := minBandwidth(meta.Bandwidth)
		if minBW > 0 && minBW < req.MinMetaBW {
			return false
		}
	}

	return true
}

// totalLatency sums all latency entries, skipping unset values.
// Returns -1 if no latency data is available.
func totalLatency(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return -1
	}

	var total time.Duration
	hasAny := false

	for _, l := range latencies {
		if l >= 0 { // LatencyUnset = -1
			total += l
			hasAny = true
		}
	}

	if !hasAny {
		return -1
	}

	return total
}

// minBandwidth returns the minimum bandwidth along the path.
// Returns 0 if no bandwidth data is available.
func minBandwidth(bandwidths []uint64) uint64 {
	if len(bandwidths) == 0 {
		return 0
	}

	var min uint64
	for _, bw := range bandwidths {
		if bw == 0 {
			continue
		}
		if min == 0 || bw < min {
			min = bw
		}
	}

	return min
}
