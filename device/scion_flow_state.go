package device

import (
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
	"golang.zx2c4.com/wireguard/flow"
	"golang.zx2c4.com/wireguard/scionlog"
	"golang.zx2c4.com/wireguard/translator/header_parsing"
)

// FlowPathsState tells the frontend whether paths for a flow are available
// ("ready"), still being fetched ("pending"), absent ("empty") or failed ("error").
type FlowPathsState string

const (
	FlowPathsReady   FlowPathsState = "ready"
	FlowPathsPending FlowPathsState = "pending"
	FlowPathsEmpty   FlowPathsState = "empty"
	FlowPathsError   FlowPathsState = "error"
)

// OverrideState describes a manual path override for a flow: "inactive" (none),
// "active" (override is the effective path) or "stale" (override fingerprint
// no longer among the selectable paths).
type OverrideState string

const (
	OverrideInactive OverrideState = "inactive"
	OverrideActive   OverrideState = "active"
	OverrideStale    OverrideState = "stale"
)

// PolicyMode describes which path policy was applied when listing paths.
type PolicyMode string

const (
	PolicyNone       PolicyMode = "none"
	PolicyDefault    PolicyMode = "default"
	PolicyConfigured PolicyMode = "configured"
)

// FlowPathDTO is the JSON form of one SCION path offered for a flow. Fingerprint
// identifies the path (hash over its interface sequence, see
// pathpool.WrapSnetPath) and is used by the frontend to request an override.
type FlowPathDTO struct {
	Fingerprint string   `json:"fingerprint"`
	Display     string   `json:"display,omitempty"`
	NextHop     string   `json:"nextHop,omitempty"`
	Expiry      string   `json:"expiry,omitempty"`
	MTU         *uint16  `json:"mtu,omitempty"`
	Interfaces  []string `json:"interfaces,omitempty"`

	LatencyMicros []int64  `json:"latencyMicros,omitempty"`
	BandwidthKbps []uint64 `json:"bandwidthKbps,omitempty"`
	Geo           []GeoDTO `json:"geo,omitempty"`
	LinkType      []string `json:"linkType,omitempty"`
	InternalHops  []uint32 `json:"internalHops,omitempty"`
	Notes         []string `json:"notes,omitempty"`

	TotalLatencyMicros *int64  `json:"totalLatencyMicros,omitempty"`
	LatencyComplete    *bool   `json:"latencyComplete,omitempty"`
	BottleneckKbps     *uint64 `json:"bottleneckKbps,omitempty"`
	BandwidthComplete  *bool   `json:"bandwidthComplete,omitempty"`
	InterAsLinks       int     `json:"interAsLinks"`
}

// GeoDTO is the geographic location of one hop from the path metadata.
type GeoDTO struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Address   string  `json:"address,omitempty"`
}

// FlowPathsResult is the JSON response of wgGetFlowPaths: the selectable paths
// of one SCION flow plus policy and override state.
type FlowPathsResult struct {
	FlowID                uint64         `json:"flowId"`
	State                 FlowPathsState `json:"state"`
	Paths                 []FlowPathDTO  `json:"paths"`
	Error                 string         `json:"error,omitempty"`
	PolicyName            string         `json:"policyName,omitempty"`
	PolicyMode            PolicyMode     `json:"policyMode"`
	PolicyFallbackApplied bool           `json:"policyFallbackApplied"`

	OverrideState        OverrideState `json:"overrideState"`
	OverrideFingerprint  string        `json:"overrideFingerprint,omitempty"`
	EffectiveFingerprint string        `json:"effectiveFingerprint,omitempty"`
}

// SCIONEgressState remembers the SCION source and destination IA of a flow so
// the path list for that flow can later be looked up in the path pool.
type SCIONEgressState struct {
	FlowID flow.ID
	SrcIA  addr.IA
	DstIA  addr.IA
}

// rememberSCIONEgress stores the IA pair for a SCION flow (first writer wins;
// conflicting later values are only logged). Used by SCIONPathsForFlow.
func (device *Device) rememberSCIONEgress(flowID flow.ID, srcIA, dstIA addr.IA) {
	device.scionFlowMu.Lock()
	defer device.scionFlowMu.Unlock()

	if device.scionFlowStates == nil {
		device.scionFlowStates = make(map[flow.ID]SCIONEgressState)
	}

	if existing, ok := device.scionFlowStates[flowID]; ok {
		if existing.SrcIA == srcIA && existing.DstIA == dstIA {
			return
		}
		if device.scionLog != nil {
			device.scionLog.Debugf(scionlog.ComponentFlow,
				"[SCION-FLOW] flowID=%d conflicting IA: existing=%s->%s new=%s->%s preserving first",
				flowID, existing.SrcIA, existing.DstIA, srcIA, dstIA)
		}
		return
	}

	device.scionFlowStates[flowID] = SCIONEgressState{
		FlowID: flowID,
		SrcIA:  srcIA,
		DstIA:  dstIA,
	}
}

// getSCIONEgress returns the IA pair stored for a flow, if any.
func (device *Device) getSCIONEgress(flowID flow.ID) (SCIONEgressState, bool) {
	device.scionFlowMu.RLock()
	defer device.scionFlowMu.RUnlock()

	state, ok := device.scionFlowStates[flowID]
	return state, ok
}

// SCIONFlowKey is the canonical identity of a SCION TCP/UDP flow as it
// appears on the wire. It uses the actual SCION hosts/ports/IA written by
// TranslateEgress, not the original fd42 addresses.
type SCIONFlowKey struct {
	Protocol uint8
	IA_A     addr.IA
	HostA    netip.Addr
	PortA    uint16
	IA_B     addr.IA
	HostB    netip.Addr
	PortB    uint16
}

// scionEndpoint is one side of a SCION flow on the wire (IA + host + port).
type scionEndpoint struct {
	IA   addr.IA
	Host netip.Addr
	Port uint16
}

// less orders SCION endpoints by IA, then host, then port (for canonical keys).
func (e scionEndpoint) less(o scionEndpoint) bool {
	if e.IA != o.IA {
		return e.IA < o.IA
	}
	if c := e.Host.Compare(o.Host); c != 0 {
		return c < 0
	}
	return e.Port < o.Port
}

// makeSCIONFlowKey builds the canonical SCIONFlowKey: both endpoints are sorted
// so that egress (src->dst) and the ingress reply (dst->src) produce the same key.
func makeSCIONFlowKey(proto uint8, ia1 addr.IA, host1 netip.Addr, port1 uint16, ia2 addr.IA, host2 netip.Addr, port2 uint16) SCIONFlowKey {
	ep1 := scionEndpoint{IA: ia1, Host: host1, Port: port1}
	ep2 := scionEndpoint{IA: ia2, Host: host2, Port: port2}
	if ep2.less(ep1) {
		ep1, ep2 = ep2, ep1
	}
	return SCIONFlowKey{
		Protocol: proto,
		IA_A:     ep1.IA,
		HostA:    ep1.Host,
		PortA:    ep1.Port,
		IA_B:     ep2.IA,
		HostB:    ep2.Host,
		PortB:    ep2.Port,
	}
}

// rememberSCIONFlow registers the SCION wire tuple of a TCP/UDP flow in
// scionFlowIndex so that inbound SCION packets can be matched back to the flow
// (lookupSCIONFlow). A key can map to several flow IDs; this is logged as
// AMBIGUOUS and makes later lookups fail with SCIONLookupAmbiguous.
func (device *Device) rememberSCIONFlow(flowID flow.ID, proto uint8, srcIA, dstIA addr.IA, srcHost, dstHost netip.Addr, srcPort, dstPort uint16) {
	if proto != flow.ProtocolTCP && proto != flow.ProtocolUDP {
		return
	}
	if !srcHost.IsValid() || !dstHost.IsValid() {
		return
	}
	key := makeSCIONFlowKey(proto, srcIA, srcHost, srcPort, dstIA, dstHost, dstPort)
	device.scionFlowMu.Lock()
	defer device.scionFlowMu.Unlock()
	if device.scionFlowIndex == nil {
		device.scionFlowIndex = make(map[SCIONFlowKey]map[flow.ID]struct{})
	}
	set, ok := device.scionFlowIndex[key]
	if !ok {
		set = make(map[flow.ID]struct{})
		device.scionFlowIndex[key] = set
	}
	if _, exists := set[flowID]; exists {
		return
	}
	set[flowID] = struct{}{}
	if device.scionLog != nil {
		if len(set) == 1 {
			device.scionLog.Debugf(scionlog.ComponentFlow,
				"[SCION-FLOW] register flow=%d class=%s scion=%s,%s:%d -> %s,%s:%d",
				flowID, trafficClassString(proto, flowID, device), srcIA, srcHost.String(), srcPort, dstIA, dstHost.String(), dstPort)
		} else {
			device.scionLog.Debugf(scionlog.ComponentFlow,
				"[SCION-FLOW] AMBIGUOUS key proto=%d %s,%s:%d <-> %s,%s:%d matches=%d newFlow=%d",
				proto, key.IA_A, key.HostA.String(), key.PortA, key.IA_B, key.HostB.String(), key.PortB, len(set), flowID)
		}
	}
}

// trafficClassString returns "plain", "mapped", "native" or "unclassified" for a
// flow ID (log helper; proto is unused).
func trafficClassString(proto uint8, flowID flow.ID, device *Device) string {
	if snap, ok := device.flowManager.GetByID(flowID); ok {
		switch snap.TrafficClass {
		case flow.ClassPlainIP:
			return "plain"
		case flow.ClassMappedSCION:
			return "mapped"
		case flow.ClassNativeSCION:
			return "native"
		default:
			return "unclassified"
		}
	}
	return "unknown"
}

// SCIONLookupResult is the outcome of an ingress flow lookup: no entry (Miss),
// exactly one flow (Hit) or more than one flow for the same key (Ambiguous).
type SCIONLookupResult int

const (
	SCIONLookupMiss SCIONLookupResult = iota
	SCIONLookupHit
	SCIONLookupAmbiguous
)

// lookupSCIONFlow resolves the SCION wire tuple of an inbound TCP/UDP packet to
// the flow created on egress. Only TCP/UDP with valid hosts are considered.
// Returns Miss, Ambiguous (more than one flow) or Hit plus the flow snapshot.
func (device *Device) lookupSCIONFlow(proto uint8, srcIA, dstIA addr.IA, srcHost, dstHost netip.Addr, srcPort, dstPort uint16) (flow.Snapshot, SCIONLookupResult) {
	if proto != flow.ProtocolTCP && proto != flow.ProtocolUDP {
		return flow.Snapshot{}, SCIONLookupMiss
	}
	if !srcHost.IsValid() || !dstHost.IsValid() {
		return flow.Snapshot{}, SCIONLookupMiss
	}
	key := makeSCIONFlowKey(proto, srcIA, srcHost, srcPort, dstIA, dstHost, dstPort)
	device.scionFlowMu.RLock()
	set, ok := device.scionFlowIndex[key]
	var id flow.ID
	var n int
	if ok {
		n = len(set)
		for k := range set {
			id = k
			break
		}
	}
	device.scionFlowMu.RUnlock()
	if !ok || n == 0 {
		return flow.Snapshot{}, SCIONLookupMiss
	}
	if n > 1 {
		return flow.Snapshot{}, SCIONLookupAmbiguous
	}
	snap, ok := device.flowManager.GetByID(id)
	if !ok {
		return flow.Snapshot{}, SCIONLookupMiss
	}
	return snap, SCIONLookupHit
}

const (
	SCMPFamilyEcho       = header_parsing.SCMPFamilyEcho
	SCMPFamilyTraceroute = header_parsing.SCMPFamilyTraceroute
)

// SCMPInfoKey identifies an SCMP echo/traceroute exchange by family, local IA,
// local host, identifier and sequence number. Because the sequence number is
// part of the key, every single echo request registers its own entry.
type SCMPInfoKey struct {
	Family     header_parsing.SCMPInfoFamily
	LocalIA    addr.IA
	LocalHost  netip.Addr
	Identifier uint16
	Sequence   uint16
}

// rememberSCMPInfo registers an outgoing SCMP echo/traceroute request in
// scmpInfoIndex so the reply can be matched back to the flow (lookupSCMPInfo).
func (device *Device) rememberSCMPInfo(flowID flow.ID, family header_parsing.SCMPInfoFamily, localIA addr.IA, localHost netip.Addr, identifier, sequence uint16) {
	if !localHost.IsValid() {
		return
	}
	key := SCMPInfoKey{Family: family, LocalIA: localIA, LocalHost: localHost, Identifier: identifier, Sequence: sequence}
	device.scionFlowMu.Lock()
	defer device.scionFlowMu.Unlock()
	if device.scmpInfoIndex == nil {
		device.scmpInfoIndex = make(map[SCMPInfoKey]map[flow.ID]struct{})
	}
	set, ok := device.scmpInfoIndex[key]
	if !ok {
		set = make(map[flow.ID]struct{})
		device.scmpInfoIndex[key] = set
	}
	if _, exists := set[flowID]; exists {
		return
	}
	set[flowID] = struct{}{}
	if device.scionLog != nil {
		if len(set) == 1 {
			device.scionLog.Debugf(scionlog.ComponentFlow, "[SCION-FLOW] register flow=%d class=%s proto=SCMP family=%d id=%d seq=%d local=%s,%s", flowID, trafficClassStringForFlow(flowID, device), family, identifier, sequence, localIA, localHost.String())
		} else {
			device.scionLog.Debugf(scionlog.ComponentFlow, "[SCION-FLOW] AMBIGUOUS SCMP key family=%d local=%s,%s id=%d seq=%d matches=%d", family, localIA, localHost.String(), identifier, sequence, len(set))
		}
	}
}

// trafficClassStringForFlow returns "plain", "mapped", "native" or
// "unclassified" for a flow ID (log helper).
func trafficClassStringForFlow(flowID flow.ID, device *Device) string {
	if snap, ok := device.flowManager.GetByID(flowID); ok {
		switch snap.TrafficClass {
		case flow.ClassPlainIP:
			return "plain"
		case flow.ClassMappedSCION:
			return "mapped"
		case flow.ClassNativeSCION:
			return "native"
		default:
			return "unclassified"
		}
	}
	return "unknown"
}

// lookupSCMPInfo resolves an inbound SCMP echo/traceroute reply to the flow of
// the original request. Returns Miss, Ambiguous or Hit plus the flow snapshot.
func (device *Device) lookupSCMPInfo(family header_parsing.SCMPInfoFamily, localIA addr.IA, localHost netip.Addr, identifier, sequence uint16) (flow.Snapshot, SCIONLookupResult) {
	if !localHost.IsValid() {
		return flow.Snapshot{}, SCIONLookupMiss
	}
	key := SCMPInfoKey{Family: family, LocalIA: localIA, LocalHost: localHost, Identifier: identifier, Sequence: sequence}
	device.scionFlowMu.RLock()
	set, ok := device.scmpInfoIndex[key]
	var id flow.ID
	var n int
	if ok {
		n = len(set)
		for k := range set {
			id = k
			break
		}
	}
	device.scionFlowMu.RUnlock()
	if !ok || n == 0 {
		return flow.Snapshot{}, SCIONLookupMiss
	}
	if n > 1 {
		return flow.Snapshot{}, SCIONLookupAmbiguous
	}
	snap, ok := device.flowManager.GetByID(id)
	if !ok {
		return flow.Snapshot{}, SCIONLookupMiss
	}
	return snap, SCIONLookupHit
}
