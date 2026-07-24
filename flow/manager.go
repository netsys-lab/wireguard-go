package flow

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

type ID uint64

type Status string

const (
	StatusActive Status = "active"
)

type EgressKind string

const (
	EgressUnknown EgressKind = "unknown"
	EgressIP      EgressKind = "ip"
	EgressSCION   EgressKind = "scion"
)

type Flow struct {
	id        ID
	ipVersion uint8
	protocol  uint8
	endpointA Endpoint
	endpointB Endpoint

	localEndpoint  Endpoint
	remoteEndpoint Endpoint
	scionDstIP     netip.Addr

	status     Status
	egressKind EgressKind
	srcIA      string
	dstIA      string
	txPackets  uint64
	txBytes    uint64
	rxPackets  uint64
	rxBytes    uint64
	createdAt  time.Time
	lastSeen   time.Time
}

func (f *Flow) snapshot() Snapshot {
	return Snapshot{
		ID:             f.id,
		IPVersion:      f.ipVersion,
		Protocol:       f.protocol,
		EndpointA:      f.endpointA,
		EndpointB:      f.endpointB,
		LocalEndpoint:  f.localEndpoint,
		RemoteEndpoint: f.remoteEndpoint,
		SCIONDstIP:     f.scionDstIP,
		Status:         f.status,
		EgressKind:     f.egressKind,
		SrcIA:          f.srcIA,
		DstIA:          f.dstIA,
		TxPackets:      f.txPackets,
		TxBytes:        f.txBytes,
		RxPackets:      f.rxPackets,
		RxBytes:        f.rxBytes,
		CreatedAt:      f.createdAt,
		LastSeen:       f.lastSeen,
	}
}

// enrichSCIONMetadata copies SCION-specific metadata from a packet into the
// flow when the corresponding flow fields are still empty (first-writer-wins).
// It does not change endpointA/endpointB, localEndpoint/remoteEndpoint,
// counters, or timestamps.
func (f *Flow) enrichSCIONMetadata(metadata PacketMetadata) {
	if f.srcIA == "" && metadata.SrcIA != "" {
		f.srcIA = metadata.SrcIA
	}
	if f.dstIA == "" && metadata.DstIA != "" {
		f.dstIA = metadata.DstIA
	}
	if !f.scionDstIP.IsValid() && metadata.SCIONDstIP.IsValid() {
		f.scionDstIP = metadata.SCIONDstIP
	}
}

// setEgressKind sets the egress kind on creation or promotes unknown -> known.
// It does not silently overwrite a non-unknown kind with a different non-unknown kind.
func (f *Flow) setEgressKind(kind EgressKind) {
	if f.egressKind == EgressUnknown || f.egressKind == "" {
		f.egressKind = kind
	}
}

type Manager struct {
	mu         sync.RWMutex
	nextID     ID
	flowsByKey map[Key]*Flow
	flowsByID  map[ID]*Flow
}

func NewManager() *Manager {
	return &Manager{
		nextID:     1,
		flowsByKey: make(map[Key]*Flow),
		flowsByID:  make(map[ID]*Flow),
	}
}

func (m *Manager) ObserveTx(metadata PacketMetadata, packetLength int, egressKind EgressKind) (Snapshot, bool) {
	key := newKey(metadata.IPVersion, metadata.Protocol, metadata.Source, metadata.Destination)

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	if flow, ok := m.flowsByKey[key]; ok {
		flow.txPackets++
		flow.txBytes += uint64(packetLength)
		flow.lastSeen = now
		flow.setEgressKind(egressKind)
		flow.enrichSCIONMetadata(metadata)
		return flow.snapshot(), false
	}

	id := m.nextID
	m.nextID++

	flow := &Flow{
		id:             id,
		ipVersion:      metadata.IPVersion,
		protocol:       metadata.Protocol,
		endpointA:      key.endpointA,
		endpointB:      key.endpointB,
		localEndpoint:  metadata.Source,
		remoteEndpoint: metadata.Destination,
		scionDstIP:     metadata.SCIONDstIP,
		status:         StatusActive,
		egressKind:     egressKind,
		srcIA:          metadata.SrcIA,
		dstIA:          metadata.DstIA,
		txPackets:      1,
		txBytes:        uint64(packetLength),
		createdAt:      now,
		lastSeen:       now,
	}

	m.flowsByKey[key] = flow
	m.flowsByID[id] = flow

	return flow.snapshot(), true
}

func (m *Manager) ObserveRx(metadata PacketMetadata, packetLength int, egressKind EgressKind) (Snapshot, bool) {
	key := newKey(metadata.IPVersion, metadata.Protocol, metadata.Source, metadata.Destination)

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	if flow, ok := m.flowsByKey[key]; ok {
		flow.rxPackets++
		flow.rxBytes += uint64(packetLength)
		flow.lastSeen = now
		flow.setEgressKind(egressKind)
		flow.enrichSCIONMetadata(metadata)
		return flow.snapshot(), false
	}

	id := m.nextID
	m.nextID++

	flow := &Flow{
		id:             id,
		ipVersion:      metadata.IPVersion,
		protocol:       metadata.Protocol,
		endpointA:      key.endpointA,
		endpointB:      key.endpointB,
		localEndpoint:  metadata.Destination,
		remoteEndpoint: metadata.Source,
		scionDstIP:     metadata.SCIONDstIP,
		status:         StatusActive,
		egressKind:     egressKind,
		srcIA:          metadata.SrcIA,
		dstIA:          metadata.DstIA,
		rxPackets:      1,
		rxBytes:        uint64(packetLength),
		createdAt:      now,
		lastSeen:       now,
	}

	m.flowsByKey[key] = flow
	m.flowsByID[id] = flow

	return flow.snapshot(), true
}

func (m *Manager) GetByID(id ID) (Snapshot, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	flow, ok := m.flowsByID[id]
	if !ok {
		return Snapshot{}, false
	}
	return flow.snapshot(), true
}

func (m *Manager) Snapshot() []Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Snapshot, 0, len(m.flowsByID))
	for _, flow := range m.flowsByID {
		result = append(result, flow.snapshot())
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	return result
}
