package flow

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

func TestDTOEgressKindIP(t *testing.T) {
	s := Snapshot{
		ID:         1,
		IPVersion:  4,
		Protocol:   ProtocolTCP,
		EndpointA:  Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		EndpointB:  Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
		Status:     StatusActive,
		EgressKind: EgressIP,
		TxPackets:  5,
		TxBytes:    500,
		CreatedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:   time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
	}
	dto := MapSnapshotToDTO(s)
	raw, err := json.Marshal(dto)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	ek, ok := decoded["egressKind"]
	if !ok {
		t.Fatal("missing egressKind field")
	}
	if ek != "ip" {
		t.Errorf("egressKind = %v, want ip", ek)
	}
}

func TestDTOEgressKindSCION(t *testing.T) {
	s := Snapshot{
		ID:         2,
		IPVersion:  6,
		Protocol:   ProtocolUDP,
		EndpointA:  Endpoint{Addr: netip.MustParseAddr("fd42:42:42::70"), Port: 49152},
		EndpointB:  Endpoint{Addr: netip.MustParseAddr("fc04:7800:4a00::ffff:a2c:1947"), Port: 443},
		Status:     StatusActive,
		EgressKind: EgressSCION,
		TxPackets:  10,
		TxBytes:    2000,
		CreatedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:   time.Date(2026, 1, 1, 0, 0, 2, 0, time.UTC),
	}
	dto := MapSnapshotToDTO(s)
	raw, err := json.Marshal(dto)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	ek, ok := decoded["egressKind"]
	if !ok {
		t.Fatal("missing egressKind field")
	}
	if ek != "scion" {
		t.Errorf("egressKind = %v, want scion", ek)
	}
}

func TestDTOEgressKindUnknownSerializes(t *testing.T) {
	s := Snapshot{
		ID:         3,
		IPVersion:  4,
		Protocol:   ProtocolTCP,
		EndpointA:  Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		EndpointB:  Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
		Status:     StatusActive,
		EgressKind: EgressUnknown,
		TxPackets:  0,
		TxBytes:    0,
		CreatedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	dto := MapSnapshotToDTO(s)
	raw, err := json.Marshal(dto)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	ek, ok := decoded["egressKind"]
	if !ok {
		t.Fatal("missing egressKind field")
	}
	if ek != "unknown" {
		t.Errorf("egressKind = %v, want unknown", ek)
	}
}

func TestDTOEgressKindZeroValueDefaultsUnknown(t *testing.T) {
	s := Snapshot{
		ID:         4,
		IPVersion:  4,
		Protocol:   ProtocolTCP,
		EndpointA:  Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		EndpointB:  Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
		Status:     StatusActive,
		EgressKind: "",
		TxPackets:  0,
		TxBytes:    0,
		CreatedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	dto := MapSnapshotToDTO(s)
	raw, err := json.Marshal(dto)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	ek, ok := decoded["egressKind"]
	if !ok {
		t.Fatal("missing egressKind field")
	}
	if ek != "unknown" {
		t.Errorf("egressKind = %v, want unknown", ek)
	}
}

func TestDTOEmptyFlowList(t *testing.T) {
	resp := FlowListResponse{Flows: []FlowDTO{}}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["error"]; ok {
		t.Error("unexpected error field in empty response")
	}
}
