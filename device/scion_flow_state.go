package device

import (
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

type FlowPathDTO struct {
	Fingerprint  string    `json:"fingerprint"`
	Display      string    `json:"display"`
	Current      bool      `json:"current"`
	NextHop      string    `json:"nextHop,omitempty"`
	Expiry       string    `json:"expiry,omitempty"`
	MTU          uint16    `json:"mtu,omitempty"`
	Interfaces   []string  `json:"interfaces,omitempty"`
	LatencyMs    []float64 `json:"latencyMs,omitempty"`
	Bandwidth    []uint64  `json:"bandwidth,omitempty"`
	Geo          []GeoDTO  `json:"geo,omitempty"`
	LinkType     []string  `json:"linkType,omitempty"`
	InternalHops []uint32  `json:"internalHops,omitempty"`
	Notes        []string  `json:"notes,omitempty"`
}

type GeoDTO struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Address   string  `json:"address,omitempty"`
}

type FlowPathsResult struct {
	FlowID uint64         `json:"flowId"`
	State  FlowPathsState `json:"state"`
	Paths  []FlowPathDTO  `json:"paths"`
	Error  string         `json:"error,omitempty"`
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
