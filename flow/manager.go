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

type Flow struct {
	id         ID
	ipVersion  uint8
	protocol   uint8
	endpointA  Endpoint
	endpointB  Endpoint
	status     Status
	txPackets  uint64
	txBytes    uint64
	rxPackets  uint64
	rxBytes    uint64
	createdAt  time.Time
	lastSeen   time.Time
}

func (f *Flow) snapshot() Snapshot {
	return Snapshot{
		ID:        f.id,
		IPVersion: f.ipVersion,
		Protocol:  f.protocol,
		EndpointA: f.endpointA,
		EndpointB: f.endpointB,
		Status:    f.status,
		TxPackets: f.txPackets,
		TxBytes:   f.txBytes,
		RxPackets: f.rxPackets,
		RxBytes:   f.rxBytes,
		CreatedAt: f.createdAt,
		LastSeen:  f.lastSeen,
	}
}

type Manager struct {
	mu        sync.RWMutex
	nextID    ID
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

func (m *Manager) ObserveTx(metadata PacketMetadata, packetLength int) (Snapshot, bool) {
	key := newKey(metadata.IPVersion, metadata.Protocol, metadata.Source, metadata.Destination)

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	if flow, ok := m.flowsByKey[key]; ok {
		flow.txPackets++
		flow.txBytes += uint64(packetLength)
		flow.lastSeen = now
		return flow.snapshot(), false
	}

	id := m.nextID
	m.nextID++

	flow := &Flow{
		id:        id,
		ipVersion: metadata.IPVersion,
		protocol:  metadata.Protocol,
		endpointA: key.endpointA,
		endpointB: key.endpointB,
		status:    StatusActive,
		txPackets: 1,
		txBytes:   uint64(packetLength),
		createdAt: now,
		lastSeen:  now,
	}

	m.flowsByKey[key] = flow
	m.flowsByID[id] = flow

	return flow.snapshot(), true
}

func (m *Manager) ObserveRx(metadata PacketMetadata, packetLength int) (Snapshot, bool) {
	key := newKey(metadata.IPVersion, metadata.Protocol, metadata.Source, metadata.Destination)

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	if flow, ok := m.flowsByKey[key]; ok {
		flow.rxPackets++
		flow.rxBytes += uint64(packetLength)
		flow.lastSeen = now
		return flow.snapshot(), false
	}

	id := m.nextID
	m.nextID++

	flow := &Flow{
		id:        id,
		ipVersion: metadata.IPVersion,
		protocol:  metadata.Protocol,
		endpointA: key.endpointA,
		endpointB: key.endpointB,
		status:    StatusActive,
		rxPackets: 1,
		rxBytes:   uint64(packetLength),
		createdAt: now,
		lastSeen:  now,
	}

	m.flowsByKey[key] = flow
	m.flowsByID[id] = flow

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
