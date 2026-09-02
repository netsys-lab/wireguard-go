package flow

import (
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

	// Phase 1: Try to find existing flow with read lock
	m.mu.RLock()
	if flow, ok := m.flowsByKey[key]; ok {
		// Existing flow: update counters atomically (no lock)
		flow.txPackets.Add(1)
		flow.txBytes.Add(uint64(packetLength))
		flow.lastSeenNano.Store(time.Now().UnixNano())
		flow.setEgressKind(egressKind)
		flow.enrichSCIONMetadata(metadata)
		m.mu.RUnlock()
		return flow.snapshot(), false
	}
	m.mu.RUnlock()

	// Phase 2: Flow not found; acquire exclusive lock to create it
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check: another goroutine may have created it while we were unlocked
	if flow, ok := m.flowsByKey[key]; ok {
		flow.txPackets.Add(1)
		flow.txBytes.Add(uint64(packetLength))
		flow.lastSeenNano.Store(time.Now().UnixNano())
		flow.setEgressKind(egressKind)
		flow.enrichSCIONMetadata(metadata)
		return flow.snapshot(), false
	}

	// Create new flow
	id := m.nextID
	m.nextID++

	now := time.Now()
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
		trafficClass:   ClassUnclassified,
		srcIA:          metadata.SrcIA,
		dstIA:          metadata.DstIA,
		createdAt:      now,
	}

	// Initialize atomic counters
	flow.txPackets.Store(1)
	flow.txBytes.Store(uint64(packetLength))
	flow.lastSeenNano.Store(now.UnixNano())

	m.flowsByKey[key] = flow
	m.flowsByID[id] = flow

	return flow.snapshot(), true
}

func (m *Manager) ObserveRx(metadata PacketMetadata, packetLength int, egressKind EgressKind) (Snapshot, bool) {
	key := newKey(metadata.IPVersion, metadata.Protocol, metadata.Source, metadata.Destination)

	// Phase 1: Try to find existing flow with read lock
	m.mu.RLock()
	if flow, ok := m.flowsByKey[key]; ok {
		// Existing flow: update counters atomically (no lock)
		flow.rxPackets.Add(1)
		flow.rxBytes.Add(uint64(packetLength))
		flow.lastSeenNano.Store(time.Now().UnixNano())
		flow.setEgressKind(egressKind)
		flow.enrichSCIONMetadata(metadata)
		m.mu.RUnlock()
		return flow.snapshot(), false
	}
	m.mu.RUnlock()

	// Phase 2: Flow not found; acquire exclusive lock to create it
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check: another goroutine may have created it while we were unlocked
	if flow, ok := m.flowsByKey[key]; ok {
		flow.rxPackets.Add(1)
		flow.rxBytes.Add(uint64(packetLength))
		flow.lastSeenNano.Store(time.Now().UnixNano())
		flow.setEgressKind(egressKind)
		flow.enrichSCIONMetadata(metadata)
		return flow.snapshot(), false
	}

	// Create new flow
	id := m.nextID
	m.nextID++

	now := time.Now()
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
		trafficClass:   ClassUnclassified,
		srcIA:          metadata.SrcIA,
		dstIA:          metadata.DstIA,
		createdAt:      now,
	}

	// Initialize atomic counters
	flow.rxPackets.Store(1)
	flow.rxBytes.Store(uint64(packetLength))
	flow.lastSeenNano.Store(now.UnixNano())

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
