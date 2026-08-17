// Package pathpolicy implements the scitra-policy.json(5) SCION path policy
// configuration system. It provides matcher-based policy selection, ACL and
// sequence filtering, requirements checking, and multi-key path ordering.
package pathpolicy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// PolicyFile is the top-level JSON structure of a scitra-policy.json file.
type PolicyFile struct {
	Matchers []Matcher          `json:"matchers"`
	Policies map[string]*Policy `json:"policies"`

	// policyOrder preserves document order for validation of extends/failover.
	policyOrder []string
}

// Matcher selects a policy based on packet/flow attributes.
// Matchers are tried in document order; the first full match wins.
type Matcher struct {
	Destination  string `json:"destination,omitempty"`   // [ISD-ASN,IP]:Port
	Source       string `json:"source,omitempty"`        // [ISD-ASN,IP]:Port
	Protocol     string `json:"protocol,omitempty"`      // "tcp" or "udp"
	TrafficClass *uint8 `json:"traffic_class,omitempty"` // 6-bit DSCP value
	PolicyName   string `json:"policy"`
}

// Policy defines filtering and sorting rules for SCION paths.
type Policy struct {
	Extends      string        `json:"extends,omitempty"`
	Failover     string        `json:"failover,omitempty"`
	ACL          []string      `json:"acl,omitempty"`
	Sequence     string        `json:"sequence,omitempty"`
	Requirements *Requirements `json:"requirements,omitempty"`
	Ordering     []string      `json:"ordering,omitempty"`
}

// Requirements specifies minimum/maximum thresholds for path metadata.
type Requirements struct {
	MinMTU     uint16 `json:"min_mtu,omitempty"`      // minimum SCION path MTU in bytes
	MaxMetaLat uint64 `json:"max_meta_lat,omitempty"` // maximum path latency in ms (static metadata)
	MinMetaBW  uint64 `json:"min_meta_bw,omitempty"`  // minimum path bandwidth in kbit/s (static metadata)
}

// ResolvedPolicy is a fully resolved policy with all inherited rules applied.
type ResolvedPolicy struct {
	Name         string
	ACL          []string
	Sequence     string
	Requirements *Requirements
	Ordering     []string
	Failover     string
}

// LoadPolicyFile reads and parses a scitra-policy.json file from disk.
func LoadPolicyFile(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file %s: %w", path, err)
	}

	return ParsePolicyFile(data)
}

// ParsePolicyFile parses a scitra-policy.json document from raw bytes.
// It validates structure and ordering constraints.
func ParsePolicyFile(data []byte) (*PolicyFile, error) {
	var pf PolicyFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse policy JSON: %w", err)
	}

	// Extract document order for policies from the raw JSON.
	// Go maps don't preserve insertion order, so we re-parse to get ordering.
	order, err := extractPolicyOrder(data)
	if err != nil {
		return nil, fmt.Errorf("extract policy order: %w", err)
	}
	pf.policyOrder = order

	if pf.Matchers == nil {
		pf.Matchers = []Matcher{}
	}
	if pf.Policies == nil {
		pf.Policies = map[string]*Policy{}
	}

	// Validate matchers reference existing policies.
	for i, m := range pf.Matchers {
		if m.PolicyName == "" {
			return nil, fmt.Errorf("matcher[%d]: missing 'policy' attribute", i)
		}
		if _, ok := pf.Policies[m.PolicyName]; !ok {
			return nil, fmt.Errorf("matcher[%d]: references undefined policy %q", i, m.PolicyName)
		}
	}

	// Validate extends/failover reference ordering.
	if err := pf.validateReferences(); err != nil {
		return nil, err
	}

	return &pf, nil
}

// validateReferences ensures extends and failover only reference policies
// that precede the referencing policy in document order.
func (pf *PolicyFile) validateReferences() error {
	seen := map[string]bool{}

	for _, name := range pf.policyOrder {
		p, ok := pf.Policies[name]
		if !ok {
			continue
		}

		if p.Extends != "" {
			if !seen[p.Extends] {
				return fmt.Errorf("policy %q extends %q which is not defined before it", name, p.Extends)
			}
		}

		if p.Failover != "" {
			if _, ok := pf.Policies[p.Failover]; !ok {
				return fmt.Errorf("policy %q failover references undefined policy %q", name, p.Failover)
			}
		}

		seen[name] = true
	}

	return nil
}

// ResolvePolicies resolves all policy inheritance chains and returns a map
// of fully resolved policies.
func (pf *PolicyFile) ResolvePolicies() (map[string]*ResolvedPolicy, error) {
	resolved := make(map[string]*ResolvedPolicy, len(pf.Policies))

	// Resolve in document order so that base policies are resolved first.
	for _, name := range pf.policyOrder {
		if err := pf.resolveOne(name, resolved); err != nil {
			return nil, err
		}
	}

	// Ensure "default" exists (implicitly defined as empty if not explicit).
	if _, ok := resolved["default"]; !ok {
		resolved["default"] = &ResolvedPolicy{Name: "default"}
	}

	return resolved, nil
}

// resolveOne resolves a single policy, recursing into its base if needed.
func (pf *PolicyFile) resolveOne(name string, resolved map[string]*ResolvedPolicy) error {
	if _, done := resolved[name]; done {
		return nil
	}

	p, ok := pf.Policies[name]
	if !ok {
		return fmt.Errorf("undefined policy: %q", name)
	}

	rp := &ResolvedPolicy{
		Name:     name,
		Failover: p.Failover,
	}

	// Start from base policy if extends is set.
	if p.Extends != "" {
		base, ok := resolved[p.Extends]
		if !ok {
			// Should have been resolved already due to document order.
			return fmt.Errorf("policy %q extends %q which was not resolved", name, p.Extends)
		}
		// Inherit from base.
		rp.ACL = copyStrings(base.ACL)
		rp.Sequence = base.Sequence
		if base.Requirements != nil {
			req := *base.Requirements
			rp.Requirements = &req
		}
		rp.Ordering = copyStrings(base.Ordering)
	}

	// Override with own rules (non-empty values override inherited ones).
	if len(p.ACL) > 0 {
		rp.ACL = p.ACL
	}
	if p.Sequence != "" {
		rp.Sequence = p.Sequence
	}
	if p.Requirements != nil {
		if rp.Requirements == nil {
			rp.Requirements = &Requirements{}
		}
		// Merge: non-zero values in extending policy override.
		if p.Requirements.MinMTU != 0 {
			rp.Requirements.MinMTU = p.Requirements.MinMTU
		}
		if p.Requirements.MaxMetaLat != 0 {
			rp.Requirements.MaxMetaLat = p.Requirements.MaxMetaLat
		}
		if p.Requirements.MinMetaBW != 0 {
			rp.Requirements.MinMetaBW = p.Requirements.MinMetaBW
		}
	}
	if len(p.Ordering) > 0 {
		rp.Ordering = p.Ordering
	}

	resolved[name] = rp
	return nil
}

// extractPolicyOrder parses the JSON to determine the document order of
// policy names inside the "policies" object.
func extractPolicyOrder(data []byte) ([]string, error) {
	// Use json.Decoder to extract key order from the "policies" object.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	policiesRaw, ok := raw["policies"]
	if !ok {
		return nil, nil
	}

	// Decode the policies object preserving key order via the decoder.
	dec := json.NewDecoder(jsonReader(policiesRaw))
	// Read opening brace.
	t, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("expected '{': %w", err)
	}
	if delim, ok := t.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("expected '{', got %v", t)
	}

	var order []string
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := t.(string)
		if !ok {
			return nil, fmt.Errorf("expected string key, got %T", t)
		}
		order = append(order, key)
		// Skip the value.
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, err
		}
	}

	return order, nil
}

// jsonReader wraps raw JSON bytes into an io.Reader for json.NewDecoder.
type jsonReaderWrapper struct {
	data []byte
	pos  int
}

func jsonReader(data json.RawMessage) *jsonReaderWrapper {
	return &jsonReaderWrapper{data: data}
}

func (r *jsonReaderWrapper) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func copyStrings(s []string) []string {
	if s == nil {
		return nil
	}
	cp := make([]string, len(s))
	copy(cp, s)
	return cp
}
