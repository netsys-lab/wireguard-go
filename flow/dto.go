package flow

import (
	"encoding/json"
	"time"
)

type FlowEndpointDTO struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

type FlowDTO struct {
	ID           uint64          `json:"id"`
	IPVersion    uint8           `json:"ipVersion"`
	Protocol     uint8           `json:"protocol"`
	EndpointA    FlowEndpointDTO `json:"endpointA"`
	EndpointB    FlowEndpointDTO `json:"endpointB"`
	LocalIP      string          `json:"localIP,omitempty"`
	LocalPort    uint16          `json:"localPort,omitempty"`
	RemoteIP     string          `json:"remoteIP,omitempty"`
	RemotePort   uint16          `json:"remotePort,omitempty"`
	SCIONDstIP   string          `json:"scionDstIP,omitempty"`
	Status       string          `json:"status"`
	EgressKind   string          `json:"egressKind"`
	TrafficClass uint8           `json:"trafficClass"`
	SrcIA        string          `json:"srcIA,omitempty"`
	DstIA        string          `json:"dstIA,omitempty"`
	TxPackets    uint64          `json:"txPackets"`
	TxBytes      uint64          `json:"txBytes"`
	RxPackets    uint64          `json:"rxPackets"`
	RxBytes      uint64          `json:"rxBytes"`
	CreatedAt    string          `json:"createdAt"`
	LastSeen     string          `json:"lastSeen"`
}

type FlowListResponse struct {
	Flows []FlowDTO `json:"flows"`
	Error string    `json:"error,omitempty"`
}

func (r FlowListResponse) MarshalJSON() ([]byte, error) {
	type alias FlowListResponse
	a := alias(r)
	if a.Flows == nil {
		a.Flows = []FlowDTO{}
	}
	return json.Marshal(a)
}

func MapSnapshotToDTO(s Snapshot) FlowDTO {
	ek := s.EgressKind
	if ek == "" {
		ek = EgressUnknown
	}
	dto := FlowDTO{
		ID:        uint64(s.ID),
		IPVersion: s.IPVersion,
		Protocol:  s.Protocol,
		EndpointA: FlowEndpointDTO{
			Address: s.EndpointA.Addr.String(),
			Port:    s.EndpointA.Port,
		},
		EndpointB: FlowEndpointDTO{
			Address: s.EndpointB.Addr.String(),
			Port:    s.EndpointB.Port,
		},
		Status:       string(s.Status),
		EgressKind:   string(ek),
		TrafficClass: uint8(s.TrafficClass),
		SrcIA:        s.SrcIA,
		DstIA:        s.DstIA,
		TxPackets:    s.TxPackets,
		TxBytes:      s.TxBytes,
		RxPackets:    s.RxPackets,
		RxBytes:      s.RxBytes,
		CreatedAt:    s.CreatedAt.Format(time.RFC3339Nano),
		LastSeen:     s.LastSeen.Format(time.RFC3339Nano),
	}
	if s.LocalEndpoint.Addr.IsValid() {
		dto.LocalIP = s.LocalEndpoint.Addr.String()
		dto.LocalPort = s.LocalEndpoint.Port
	}
	if s.RemoteEndpoint.Addr.IsValid() {
		dto.RemoteIP = s.RemoteEndpoint.Addr.String()
		dto.RemotePort = s.RemoteEndpoint.Port
	}
	if s.SCIONDstIP.IsValid() {
		dto.SCIONDstIP = s.SCIONDstIP.String()
	}
	return dto
}
