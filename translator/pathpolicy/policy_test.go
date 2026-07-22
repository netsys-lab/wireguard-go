package pathpolicy

import (
	"net"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"

	pathpool "golang.zx2c4.com/wireguard/translator/pathpool"
)

// --- Test Helpers ---

func mustIA(s string) addr.IA {
	ia, err := addr.ParseIA(s)
	if err != nil {
		panic(err)
	}
	return ia
}

func makeTestPath(src, dst addr.IA, ifaceIDs []uint64, mtu uint16, latencies []time.Duration, bandwidths []uint64) pathpool.CachedPath {
	ifaces := make([]snet.PathInterface, len(ifaceIDs))
	for i, id := range ifaceIDs {
		// Alternate IA between src and dst for interface list.
		ia := src
		if i%2 == 1 {
			ia = dst
		}
		ifaces[i] = snet.PathInterface{
			ID: iface.ID(id),
			IA: ia,
		}
	}

	meta := snet.PathMetadata{
		Interfaces: ifaces,
		MTU:        mtu,
		Expiry:     time.Now().Add(1 * time.Hour),
		Latency:    latencies,
		Bandwidth:  bandwidths,
	}

	nextHop := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 30041,
	}

	sp := path.Path{
		NextHop: nextHop,
		Meta:    meta,
		Src:     src,
		Dst:     dst,
	}

	return pathpool.CachedPath{
		Src:         src,
		Dst:         dst,
		Path:        sp,
		NextHop:     nextHop,
		Fingerprint: "test-fp",
		Expiry:      meta.Expiry,
	}
}

// makeTestPathWithIAs creates a test path with specific IA assignments per interface.
func makeTestPathWithIAs(src, dst addr.IA, ifaceEntries []snet.PathInterface, mtu uint16) pathpool.CachedPath {
	meta := snet.PathMetadata{
		Interfaces: ifaceEntries,
		MTU:        mtu,
		Expiry:     time.Now().Add(1 * time.Hour),
	}

	nextHop := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 30041,
	}

	sp := path.Path{
		NextHop: nextHop,
		Meta:    meta,
		Src:     src,
		Dst:     dst,
	}

	return pathpool.CachedPath{
		Src:         src,
		Dst:         dst,
		Path:        sp,
		NextHop:     nextHop,
		Fingerprint: "test-fp",
		Expiry:      meta.Expiry,
	}
}

// --- Policy Parsing Tests ---

func TestParsePolicyFileMinimal(t *testing.T) {
	json := `{"matchers": [], "policies": {}}`

	pf, err := ParsePolicyFile([]byte(json))
	if err != nil {
		t.Fatalf("ParsePolicyFile failed: %v", err)
	}

	if len(pf.Matchers) != 0 {
		t.Errorf("expected 0 matchers, got %d", len(pf.Matchers))
	}
	if len(pf.Policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(pf.Policies))
	}
}

func TestParsePolicyFileFullExample(t *testing.T) {
	json := `{
		"matchers": [
			{"source": "1-64512,127.0.0.1", "protocol": "udp", "traffic_class": 1, "policy": "p1"},
			{"destination": "[1-ff00:0:1,10.0.0.1]:22", "source": "1-64512", "protocol": "tcp", "policy": "p2"},
			{"destination": "[1-ff00:0:1,10.0.0.1]:80", "source": "1-64512", "protocol": "tcp", "policy": "p3"}
		],
		"policies": {
			"default": {
				"acl": ["- 666", "+"],
				"ordering": ["random", "hops_asc", "meta_bandwidth_desc"]
			},
			"p1": {
				"extends": "default",
				"requirements": {"min_mtu": 1420},
				"ordering": ["meta_latency_asc"]
			},
			"p2": {
				"extends": "default",
				"sequence": "1-64512#20 0*"
			},
			"p3": {
				"extends": "p2",
				"failover": "p2",
				"requirements": {"min_mtu": 1500}
			}
		}
	}`

	pf, err := ParsePolicyFile([]byte(json))
	if err != nil {
		t.Fatalf("ParsePolicyFile failed: %v", err)
	}

	if len(pf.Matchers) != 3 {
		t.Fatalf("expected 3 matchers, got %d", len(pf.Matchers))
	}

	if len(pf.Policies) != 4 {
		t.Fatalf("expected 4 policies, got %d", len(pf.Policies))
	}

	// Validate matchers.
	if pf.Matchers[0].Protocol != "udp" {
		t.Errorf("matcher[0] protocol: want udp, got %s", pf.Matchers[0].Protocol)
	}
	if pf.Matchers[0].PolicyName != "p1" {
		t.Errorf("matcher[0] policy: want p1, got %s", pf.Matchers[0].PolicyName)
	}
	if pf.Matchers[0].TrafficClass == nil || *pf.Matchers[0].TrafficClass != 1 {
		t.Errorf("matcher[0] traffic_class: want 1, got %v", pf.Matchers[0].TrafficClass)
	}
}

func TestParsePolicyFileInvalidExtendsOrder(t *testing.T) {
	json := `{
		"matchers": [],
		"policies": {
			"child": {
				"extends": "parent"
			},
			"parent": {
				"acl": ["+"]
			}
		}
	}`

	_, err := ParsePolicyFile([]byte(json))
	if err == nil {
		t.Fatal("expected error for invalid extends order")
	}
}

func TestParsePolicyFileInvalidMatcherPolicy(t *testing.T) {
	json := `{
		"matchers": [{"policy": "nonexistent"}],
		"policies": {}
	}`

	_, err := ParsePolicyFile([]byte(json))
	if err == nil {
		t.Fatal("expected error for matcher referencing nonexistent policy")
	}
}

// --- Policy Resolution Tests ---

func TestResolvePoliciesInheritance(t *testing.T) {
	json := `{
		"matchers": [],
		"policies": {
			"default": {
				"acl": ["- 666", "+"],
				"ordering": ["random"]
			},
			"p1": {
				"extends": "default",
				"requirements": {"min_mtu": 1420},
				"ordering": ["meta_latency_asc"]
			}
		}
	}`

	pf, err := ParsePolicyFile([]byte(json))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	resolved, err := pf.ResolvePolicies()
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	p1 := resolved["p1"]
	if p1 == nil {
		t.Fatal("p1 not resolved")
	}

	// p1 should inherit ACL from default.
	if len(p1.ACL) != 2 {
		t.Errorf("p1 ACL: want 2 rules (inherited), got %d", len(p1.ACL))
	}

	// p1 overrides ordering.
	if len(p1.Ordering) != 1 || p1.Ordering[0] != "meta_latency_asc" {
		t.Errorf("p1 Ordering: want [meta_latency_asc], got %v", p1.Ordering)
	}

	// p1 has its own requirements.
	if p1.Requirements == nil || p1.Requirements.MinMTU != 1420 {
		t.Errorf("p1 Requirements.MinMTU: want 1420, got %v", p1.Requirements)
	}
}

func TestResolvePoliciesImplicitDefault(t *testing.T) {
	json := `{"matchers": [], "policies": {}}`

	pf, err := ParsePolicyFile([]byte(json))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	resolved, err := pf.ResolvePolicies()
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	def := resolved["default"]
	if def == nil {
		t.Fatal("implicit default policy not created")
	}

	if len(def.ACL) != 0 {
		t.Errorf("implicit default ACL: want empty, got %v", def.ACL)
	}
}

// --- Hop Predicate Tests ---

func TestParseHopPredicate(t *testing.T) {
	tests := []struct {
		input   string
		wantISD uint16
		wantASN uint64
		wantIg  uint64
		wantEg  uint64
		wantErr bool
	}{
		{"0", 0, 0, 0, 0, false},
		{"1", 1, 0, 0, 0, false},
		{"666", 666, 0, 0, 0, false}, // valid ISD (fits in uint16)
		{"1-64512", 1, 64512, 0, 0, false},
		{"1-64512#20", 1, 64512, 20, 20, false},     // single IF mode
		{"1-64512#20,30", 1, 64512, 20, 30, false},
		{"1-ff00:0:110", 1, 0, 0, 0, false},         // parsed as SCION IA
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			hp, err := ParseHopPredicate(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}

			if tt.input == "1-ff00:0:110" {
				// For SCION IA, just check ISD and that ASN is non-zero.
				if hp.ISD != 1 {
					t.Errorf("ISD: want 1, got %d", hp.ISD)
				}
				if hp.ASN == 0 {
					t.Errorf("ASN: want non-zero for ff00:0:110")
				}
				return
			}

			if hp.ISD != tt.wantISD {
				t.Errorf("ISD: want %d, got %d", tt.wantISD, hp.ISD)
			}
			if hp.ASN != tt.wantASN {
				t.Errorf("ASN: want %d, got %d", tt.wantASN, hp.ASN)
			}
			if hp.Ingress != tt.wantIg {
				t.Errorf("Ingress: want %d, got %d", tt.wantIg, hp.Ingress)
			}
			if hp.Egress != tt.wantEg {
				t.Errorf("Egress: want %d, got %d", tt.wantEg, hp.Egress)
			}
		})
	}
}

func TestHopPredicateMatchInterface(t *testing.T) {
	ia := mustIA("1-ff00:0:110")

	iface := snet.PathInterface{
		IA: ia,
		ID: 20,
	}

	tests := []struct {
		name  string
		pred  string
		match bool
	}{
		{"wildcard", "0", true},
		{"ISD only match", "1", true},
		{"ISD only mismatch", "2", false},
		{"IA match", "1-ff00:0:110", true},
		{"IA mismatch", "1-ff00:0:111", false},
		{"IA+IF match", "1-ff00:0:110#20", true},
		{"IA+IF mismatch", "1-ff00:0:110#30", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hp, err := ParseHopPredicate(tt.pred)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}

			got := hp.MatchInterface(iface)
			if got != tt.match {
				t.Errorf("MatchInterface(%v) with predicate %q: want %v, got %v", iface, tt.pred, tt.match, got)
			}
		})
	}
}

// --- Matcher Tests ---

func TestMatchPacketBasic(t *testing.T) {
	tc := uint8(1)
	matchers := []Matcher{
		{
			Source:       "1-64512",
			Protocol:     "udp",
			TrafficClass: &tc,
			PolicyName:   "p1",
		},
		{
			Destination: "1-64512",
			Protocol:    "tcp",
			PolicyName:  "p2",
		},
	}

	// Should match p1: source=1-64512, protocol=udp, tc=1.
	info1 := PacketInfo{
		SrcIA:    mustIA("1-64512"),
		DstIA:    mustIA("1-ff00:0:1"),
		Protocol: "udp",
		DSCP:     1,
	}
	if got := MatchPacket(matchers, info1); got != "p1" {
		t.Errorf("expected p1, got %s", got)
	}

	// Should match p2: destination=1-64512, protocol=tcp.
	info2 := PacketInfo{
		SrcIA:    mustIA("1-ff00:0:1"),
		DstIA:    mustIA("1-64512"),
		Protocol: "tcp",
		DSCP:     0,
	}
	if got := MatchPacket(matchers, info2); got != "p2" {
		t.Errorf("expected p2, got %s", got)
	}

	// Should match default: no matcher matches.
	info3 := PacketInfo{
		SrcIA:    mustIA("2-ff00:0:1"),
		DstIA:    mustIA("2-ff00:0:2"),
		Protocol: "tcp",
		DSCP:     0,
	}
	if got := MatchPacket(matchers, info3); got != "default" {
		t.Errorf("expected default, got %s", got)
	}
}

// --- ACL Filter Tests ---

func TestFilterACLBasic(t *testing.T) {
	src := mustIA("1-ff00:0:110")
	dst := mustIA("1-ff00:0:111")

	// Path through AS 666 (should be blocked by "- 0-666" rule).
	// Use "0-666" hop predicate format: ISD=0(wildcard), ASN=666.
	blockedIA, _ := addr.IAFrom(addr.ISD(1), addr.AS(666))
	blockedPath := makeTestPathWithIAs(src, dst,
		[]snet.PathInterface{
			{IA: src, ID: 1},
			{IA: blockedIA, ID: 2},
		}, 1500)

	// Path not through AS 666 (should be allowed).
	allowedPath := makeTestPathWithIAs(src, dst,
		[]snet.PathInterface{
			{IA: src, ID: 1},
			{IA: dst, ID: 2},
		}, 1500)

	paths := []pathpool.CachedPath{blockedPath, allowedPath}
	acl := []string{"- 0-666", "+"}

	result := filterACL(acl, paths)

	if len(result) != 1 {
		t.Fatalf("expected 1 allowed path, got %d", len(result))
	}
}

func TestFilterACLAllowAll(t *testing.T) {
	src := mustIA("1-ff00:0:110")
	dst := mustIA("1-ff00:0:111")

	p := makeTestPath(src, dst, []uint64{1, 2}, 1500, nil, nil)
	paths := []pathpool.CachedPath{p}

	result := filterACL([]string{"+"}, paths)
	if len(result) != 1 {
		t.Fatalf("expected 1 path with allow-all ACL, got %d", len(result))
	}
}

func TestFilterACLDenyAll(t *testing.T) {
	src := mustIA("1-ff00:0:110")
	dst := mustIA("1-ff00:0:111")

	p := makeTestPath(src, dst, []uint64{1, 2}, 1500, nil, nil)
	paths := []pathpool.CachedPath{p}

	result := filterACL([]string{"-"}, paths)
	if len(result) != 0 {
		t.Fatalf("expected 0 paths with deny-all ACL, got %d", len(result))
	}
}

// --- Requirements Filter Tests ---

func TestFilterRequirementsMTU(t *testing.T) {
	src := mustIA("1-ff00:0:110")
	dst := mustIA("1-ff00:0:111")

	pathHighMTU := makeTestPath(src, dst, []uint64{1, 2}, 1500, nil, nil)
	pathLowMTU := makeTestPath(src, dst, []uint64{3, 4}, 1200, nil, nil)
	paths := []pathpool.CachedPath{pathHighMTU, pathLowMTU}

	req := &Requirements{MinMTU: 1420}
	result := filterRequirements(req, paths)

	if len(result) != 1 {
		t.Fatalf("expected 1 path with MTU >= 1420, got %d", len(result))
	}
}

func TestFilterRequirementsLatency(t *testing.T) {
	src := mustIA("1-ff00:0:110")
	dst := mustIA("1-ff00:0:111")

	pathLowLat := makeTestPath(src, dst, []uint64{1, 2}, 1500,
		[]time.Duration{5 * time.Millisecond, 3 * time.Millisecond}, nil)
	pathHighLat := makeTestPath(src, dst, []uint64{3, 4}, 1500,
		[]time.Duration{50 * time.Millisecond, 60 * time.Millisecond}, nil)

	paths := []pathpool.CachedPath{pathLowLat, pathHighLat}

	req := &Requirements{MaxMetaLat: 20} // max 20ms
	result := filterRequirements(req, paths)

	if len(result) != 1 {
		t.Fatalf("expected 1 path with latency <= 20ms, got %d", len(result))
	}
}

func TestFilterRequirementsBandwidth(t *testing.T) {
	src := mustIA("1-ff00:0:110")
	dst := mustIA("1-ff00:0:111")

	pathHighBW := makeTestPath(src, dst, []uint64{1, 2}, 1500, nil, []uint64{100000, 50000})
	pathLowBW := makeTestPath(src, dst, []uint64{3, 4}, 1500, nil, []uint64{1000, 500})

	paths := []pathpool.CachedPath{pathHighBW, pathLowBW}

	req := &Requirements{MinMetaBW: 10000} // min 10000 kbit/s
	result := filterRequirements(req, paths)

	if len(result) != 1 {
		t.Fatalf("expected 1 path with bandwidth >= 10000 kbit/s, got %d", len(result))
	}
}

// --- Sequence Filter Tests ---

func TestFilterSequenceBasic(t *testing.T) {
	src := mustIA("1-64512")
	dst := mustIA("1-ff00:0:111")

	// Path: 1-64512#20 -> 1-ff00:0:111#1
	matchingPath := makeTestPathWithIAs(src, dst,
		[]snet.PathInterface{
			{IA: src, ID: 20},
			{IA: dst, ID: 1},
		}, 1500)

	// Path: 1-64512#30 -> 1-ff00:0:111#1 (wrong interface)
	nonMatchingPath := makeTestPathWithIAs(src, dst,
		[]snet.PathInterface{
			{IA: src, ID: 30},
			{IA: dst, ID: 1},
		}, 1500)

	paths := []pathpool.CachedPath{matchingPath, nonMatchingPath}

	// Sequence: must start with 1-64512#20 followed by zero or more of anything.
	result := filterSequence("1-64512#20 0*", paths)

	if len(result) != 1 {
		t.Fatalf("expected 1 path matching sequence, got %d", len(result))
	}
}

func TestFilterSequenceWildcard(t *testing.T) {
	src := mustIA("1-ff00:0:110")
	dst := mustIA("1-ff00:0:111")

	p := makeTestPath(src, dst, []uint64{1, 2, 3, 4}, 1500, nil, nil)
	paths := []pathpool.CachedPath{p}

	// "0*" should match any path.
	result := filterSequence("0*", paths)
	if len(result) != 1 {
		t.Fatalf("expected 1 path with wildcard sequence, got %d", len(result))
	}
}

// --- Sort Tests ---

func TestSortByHopsAsc(t *testing.T) {
	src := mustIA("1-ff00:0:110")
	dst := mustIA("1-ff00:0:111")

	shortPath := makeTestPath(src, dst, []uint64{1, 2}, 1500, nil, nil)
	longPath := makeTestPath(src, dst, []uint64{1, 2, 3, 4, 5, 6}, 1500, nil, nil)

	paths := []pathpool.CachedPath{longPath, shortPath}
	sorted := SortPaths([]string{"hops_asc"}, paths)

	if hopCount(sorted[0]) > hopCount(sorted[1]) {
		t.Error("hops_asc: first path should have fewer hops")
	}
}

func TestSortByLatencyAsc(t *testing.T) {
	src := mustIA("1-ff00:0:110")
	dst := mustIA("1-ff00:0:111")

	fastPath := makeTestPath(src, dst, []uint64{1, 2}, 1500,
		[]time.Duration{2 * time.Millisecond}, nil)
	slowPath := makeTestPath(src, dst, []uint64{3, 4}, 1500,
		[]time.Duration{100 * time.Millisecond}, nil)

	paths := []pathpool.CachedPath{slowPath, fastPath}
	sorted := SortPaths([]string{"meta_latency_asc"}, paths)

	if pathLatency(sorted[0]) > pathLatency(sorted[1]) {
		t.Error("meta_latency_asc: first path should have lower latency")
	}
}

func TestSortByBandwidthDesc(t *testing.T) {
	src := mustIA("1-ff00:0:110")
	dst := mustIA("1-ff00:0:111")

	highBW := makeTestPath(src, dst, []uint64{1, 2}, 1500, nil, []uint64{100000})
	lowBW := makeTestPath(src, dst, []uint64{3, 4}, 1500, nil, []uint64{1000})

	paths := []pathpool.CachedPath{lowBW, highBW}
	sorted := SortPaths([]string{"meta_bandwidth_desc"}, paths)

	if pathBandwidth(sorted[0]) < pathBandwidth(sorted[1]) {
		t.Error("meta_bandwidth_desc: first path should have higher bandwidth")
	}
}

// --- Engine End-to-End Tests ---

func TestEngineSelectPathsWithFullExample(t *testing.T) {
	policyJSON := `{
		"matchers": [
			{"source": "1-64512", "protocol": "udp", "policy": "p1"}
		],
		"policies": {
			"default": {
				"acl": ["+"],
				"ordering": ["hops_asc"]
			},
			"p1": {
				"extends": "default",
				"requirements": {"min_mtu": 1420},
				"ordering": ["meta_latency_asc"]
			}
		}
	}`

	pf, err := ParsePolicyFile([]byte(policyJSON))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	engine, err := NewEngine(pf)
	if err != nil {
		t.Fatalf("engine creation failed: %v", err)
	}

	src := mustIA("1-64512")
	dst := mustIA("1-ff00:0:111")

	// Create paths with different MTUs and latencies.
	pathHighMTU_LowLat := makeTestPath(src, dst, []uint64{1, 2}, 1500,
		[]time.Duration{5 * time.Millisecond}, nil)
	pathHighMTU_HighLat := makeTestPath(src, dst, []uint64{3, 4}, 1500,
		[]time.Duration{100 * time.Millisecond}, nil)
	pathLowMTU := makeTestPath(src, dst, []uint64{5, 6}, 1200,
		[]time.Duration{1 * time.Millisecond}, nil)

	paths := []pathpool.CachedPath{pathHighMTU_HighLat, pathLowMTU, pathHighMTU_LowLat}

	info := PacketInfo{
		SrcIA:    src,
		DstIA:    dst,
		Protocol: "udp",
	}

	result := engine.SelectPaths(info, paths)

	// p1 applies: requires min_mtu 1420, sorts by latency asc.
	// pathLowMTU (MTU=1200) should be filtered out.
	// Remaining: pathHighMTU_LowLat (5ms), pathHighMTU_HighLat (100ms)
	// Sorted by latency: pathHighMTU_LowLat first.
	if len(result) != 2 {
		t.Fatalf("expected 2 paths after filtering, got %d", len(result))
	}

	// First path should be the low-latency one.
	firstLat := pathLatency(result[0])
	secondLat := pathLatency(result[1])
	if firstLat > secondLat {
		t.Errorf("paths not sorted by latency: first=%dms, second=%dms", firstLat, secondLat)
	}
}

func TestEngineSelectPathsDefaultPolicy(t *testing.T) {
	policyJSON := `{
		"matchers": [],
		"policies": {
			"default": {
				"ordering": ["hops_asc"]
			}
		}
	}`

	pf, err := ParsePolicyFile([]byte(policyJSON))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	engine, err := NewEngine(pf)
	if err != nil {
		t.Fatalf("engine creation failed: %v", err)
	}

	src := mustIA("1-ff00:0:110")
	dst := mustIA("1-ff00:0:111")

	shortPath := makeTestPath(src, dst, []uint64{1, 2}, 1500, nil, nil)
	longPath := makeTestPath(src, dst, []uint64{1, 2, 3, 4, 5, 6}, 1500, nil, nil)

	paths := []pathpool.CachedPath{longPath, shortPath}

	info := PacketInfo{
		SrcIA:    src,
		DstIA:    dst,
		Protocol: "tcp",
	}

	result := engine.SelectPaths(info, paths)

	if len(result) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(result))
	}

	// Should be sorted by hops ascending.
	if hopCount(result[0]) > hopCount(result[1]) {
		t.Error("default policy should sort by hops_asc")
	}
}

func TestEngineFailover(t *testing.T) {
	policyJSON := `{
		"matchers": [{"policy": "strict"}],
		"policies": {
			"lenient": {
				"acl": ["+"],
				"ordering": ["hops_asc"]
			},
			"strict": {
				"extends": "lenient",
				"failover": "lenient",
				"requirements": {"min_mtu": 9000}
			}
		}
	}`

	pf, err := ParsePolicyFile([]byte(policyJSON))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	engine, err := NewEngine(pf)
	if err != nil {
		t.Fatalf("engine creation failed: %v", err)
	}

	src := mustIA("1-ff00:0:110")
	dst := mustIA("1-ff00:0:111")

	// All paths have MTU 1500, which doesn't meet the strict requirement (9000).
	p := makeTestPath(src, dst, []uint64{1, 2}, 1500, nil, nil)
	paths := []pathpool.CachedPath{p}

	info := PacketInfo{
		SrcIA:    src,
		DstIA:    dst,
		Protocol: "tcp",
	}

	result := engine.SelectPaths(info, paths)

	// Strict fails (MTU 1500 < 9000), failover to lenient which accepts all.
	if len(result) != 1 {
		t.Fatalf("expected 1 path after failover, got %d", len(result))
	}
}

func TestEngineNilEngine(t *testing.T) {
	src := mustIA("1-ff00:0:110")
	dst := mustIA("1-ff00:0:111")

	p := makeTestPath(src, dst, []uint64{1, 2}, 1500, nil, nil)
	paths := []pathpool.CachedPath{p}

	var engine *Engine

	result := engine.SelectPaths(PacketInfo{}, paths)
	if len(result) != 1 {
		t.Fatalf("nil engine should return paths unchanged, got %d", len(result))
	}
}
