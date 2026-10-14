package flow

import (
	"bytes"
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

func TestDTOSerializesOrientationFields(t *testing.T) {
	s := Snapshot{
		ID:             10,
		IPVersion:      4,
		Protocol:       ProtocolUDP,
		EndpointA:      Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		EndpointB:      Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
		LocalEndpoint:  Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		RemoteEndpoint: Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
		SCIONDstIP:     netip.MustParseAddr("192.168.1.1"),
		Status:         StatusActive,
		EgressKind:     EgressSCION,
		TxPackets:      1,
		TxBytes:        100,
		CreatedAt:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSeen:       time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
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
	if v, ok := decoded["localIP"]; !ok || v != "10.0.0.2" {
		t.Errorf("localIP = %v, want 10.0.0.2", v)
	}
	if v, ok := decoded["localPort"]; !ok || v != float64(49152) {
		t.Errorf("localPort = %v, want 49152", v)
	}
	if v, ok := decoded["remoteIP"]; !ok || v != "10.0.0.3" {
		t.Errorf("remoteIP = %v, want 10.0.0.3", v)
	}
	if v, ok := decoded["remotePort"]; !ok || v != float64(443) {
		t.Errorf("remotePort = %v, want 443", v)
	}
	if v, ok := decoded["scionDstIP"]; !ok || v != "192.168.1.1" {
		t.Errorf("scionDstIP = %v, want 192.168.1.1", v)
	}
}

func TestDTOOmitsEmptyOrientationFields(t *testing.T) {
	s := Snapshot{
		ID:         11,
		IPVersion:  4,
		Protocol:   ProtocolTCP,
		EndpointA:  Endpoint{Addr: netip.MustParseAddr("10.0.0.2"), Port: 49152},
		EndpointB:  Endpoint{Addr: netip.MustParseAddr("10.0.0.3"), Port: 443},
		Status:     StatusActive,
		EgressKind: EgressIP,
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
	if bytes.Contains(raw, []byte("localIP")) {
		t.Error("expected localIP to be omitted")
	}
	if bytes.Contains(raw, []byte("localPort")) {
		t.Error("expected localPort to be omitted")
	}
	if bytes.Contains(raw, []byte("remoteIP")) {
		t.Error("expected remoteIP to be omitted")
	}
	if bytes.Contains(raw, []byte("remotePort")) {
		t.Error("expected remotePort to be omitted")
	}
	if bytes.Contains(raw, []byte("scionDstIP")) {
		t.Error("expected scionDstIP to be omitted")
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
