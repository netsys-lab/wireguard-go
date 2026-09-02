package device

import (
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
	"golang.zx2c4.com/wireguard/flow"
	"golang.zx2c4.com/wireguard/scionlog"
)

type FlowPathsState string

const (
	FlowPathsReady   FlowPathsState = "ready"
	FlowPathsPending FlowPathsState = "pending"
	FlowPathsEmpty   FlowPathsState = "empty"
	FlowPathsError   FlowPathsState = "error"
)

type OverrideState string

const (
	OverrideInactive OverrideState = "inactive"
	OverrideActive   OverrideState = "active"
	OverrideStale    OverrideState = "stale"
)

type PolicyMode string

const (
	PolicyNone       PolicyMode = "none"
	PolicyDefault    PolicyMode = "default"
	PolicyConfigured PolicyMode = "configured"
)

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

type GeoDTO struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Address   string  `json:"address,omitempty"`
}

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

type SCIONEgressState struct {
	FlowID flow.ID
	SrcIA  addr.IA
	DstIA  addr.IA
}

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

type scionEndpoint struct {
	IA   addr.IA
	Host netip.Addr
	Port uint16
}

func (e scionEndpoint) less(o scionEndpoint) bool {
	if e.IA != o.IA {
		return e.IA < o.IA
	}
	if c := e.Host.Compare(o.Host); c != 0 {
		return c < 0
	}
	return e.Port < o.Port
}

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

type SCIONLookupResult int

const (
	SCIONLookupMiss       SCIONLookupResult = iota
	SCIONLookupHit
	SCIONLookupAmbiguous
)

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
