package flow

import (
	"log"
	"sort"
	"sync"
	"time"
)

// ID is the monotonically increasing flow identifier (starting at 1). IDs are
// never reused during the lifetime of a Manager; the frontend uses them to
// address a flow (details view, path override).
type ID uint64

// Status is the lifecycle state of a flow. Currently only StatusActive exists;
// flows are never marked idle or removed.
type Status string

const (
	StatusActive Status = "active"
)

// EgressKind is the coarse transport of a flow as shown in the UI:
// "ip" (plain IP through WireGuard), "scion" (mapped or native SCION) or
// "unknown". It does NOT describe the packet direction.
type EgressKind string

const (
	EgressUnknown EgressKind = "unknown"
	EgressIP      EgressKind = "ip"
	EgressSCION   EgressKind = "scion"
)

// Manager tracks all flows of one Device. flowsByKey resolves a packet tuple to
// its flow, flowsByID serves lookups from the frontend. mu protects both maps;
// per-flow counters are atomics and are updated under the read lock.
// There is currently no expiry: entries live until the Device is closed.
type Manager struct {
	mu         sync.RWMutex
	nextID     ID
	flowsByKey map[Key]*Flow
	flowsByID  map[ID]*Flow

	// onFlowCreated is called (outside of mu) for every newly created flow.
	onFlowCreated func(Snapshot)
}

// SetOnFlowCreated registers a callback that is invoked once for every newly
// created flow, after the Manager lock has been released. The callback runs on
// the packet path and must not block (e.g. use a non-blocking channel send).
func (m *Manager) SetOnFlowCreated(fn func(Snapshot)) {
	m.mu.Lock()
	m.onFlowCreated = fn
	m.mu.Unlock()
}

// notifyCreated invokes the creation callback, if any. Must be called without
// holding m.mu.
func (m *Manager) notifyCreated(s Snapshot) {
	m.mu.RLock()
	fn := m.onFlowCreated
	m.mu.RUnlock()
	if fn != nil {
		fn(s)
	}
}

// NewManager creates an empty Manager whose first flow gets ID 1.
func NewManager() *Manager {
	return &Manager{
		nextID:     1,
		flowsByKey: make(map[Key]*Flow),
		flowsByID:  make(map[ID]*Flow),
	}
}

// ObserveTx records one outgoing packet (read from the TUN device).
// It looks the flow up by its canonical Key and, if found, increments the tx
// counters, refreshes lastSeen and fills still-empty metadata (egress kind,
// traffic class, SCION IA / destination). If no flow exists yet, a new one is
// created (double-checked under the write lock) with local=Source and
// remote=Destination of this packet. It returns a snapshot and whether the
// flow was newly created. Called from RoutineReadFromTUN in device/send.go.
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
		flow.setTrafficClass(metadata.TrafficClass)
		flow.enrichSCIONMetadata(metadata)
		m.mu.RUnlock()
		return flow.snapshot(), false
	}
	m.mu.RUnlock()

	// Phase 2: Flow not found; acquire exclusive lock to create it.
	// The creation callback must run after the lock is released; deferred
	// functions run in reverse order, so this one runs after m.mu.Unlock.
	var created *Snapshot
	defer func() {
		if created != nil {
			m.notifyCreated(*created)
		}
	}()
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check: another goroutine may have created it while we were unlocked
	if flow, ok := m.flowsByKey[key]; ok {
		flow.txPackets.Add(1)
		flow.txBytes.Add(uint64(packetLength))
		flow.lastSeenNano.Store(time.Now().UnixNano())
		flow.setEgressKind(egressKind)
		flow.setTrafficClass(metadata.TrafficClass)
		flow.enrichSCIONMetadata(metadata)
		return flow.snapshot(), false
	}

	// Create new flow
	id := m.nextID
	m.nextID++

	now := time.Now()
	tc := metadata.TrafficClass
	if tc == ClassUnclassified {
		// Default to PlainIP if not classified; caller should set explicitly.
		// EgressKind remains "scion" vs "ip" for coarse grouping.
		tc = ClassUnclassified
	}
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
		trafficClass:   tc,
		srcIA:          metadata.SrcIA,
		dstIA:          metadata.DstIA,
		createdAt:      now,
	}

	// Initialize atomic counters
	flow.txPackets.Store(1)
	flow.txBytes.Store(uint64(packetLength))
	flow.lastSeenNano.Store(now.UnixNano())

	// Outgoing packet: the socket's local side is the packet source.
	sockProto, sockSrc, sockDst := metadata.socketTuple()
	flow.initSocket(sockProto, sockSrc, sockDst)

	m.flowsByKey[key] = flow
	m.flowsByID[id] = flow

	log.Printf("[FLOW-DEBUG] [FlowManager] ObserveTx: NEW FLOW CREATED: id=%d egressKind='%s' class=%d proto=%d src=%s dst=%s scionDstIP=%s dstIA='%s'",
		id, egressKind, tc, metadata.Protocol, metadata.Source, metadata.Destination, metadata.SCIONDstIP, metadata.DstIA)

	snap := flow.snapshot()
	created = &snap
	return snap, true
}

// ObserveRx is the receive-side counterpart of ObserveTx: it increments the rx
// counters of the matching flow or creates a new flow with local=Destination and
// remote=Source (the packet came from the remote side).
// NOTE: this function is currently not called from the production receive path
// (device/receive.go), therefore RxPackets/RxBytes stay 0 in the UI.
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
		flow.setTrafficClass(metadata.TrafficClass)
		flow.enrichSCIONMetadata(metadata)
		m.mu.RUnlock()
		return flow.snapshot(), false
	}
	m.mu.RUnlock()

	// Phase 2: Flow not found; acquire exclusive lock to create it.
	// The creation callback must run after the lock is released; deferred
	// functions run in reverse order, so this one runs after m.mu.Unlock.
	var created *Snapshot
	defer func() {
		if created != nil {
			m.notifyCreated(*created)
		}
	}()
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check: another goroutine may have created it while we were unlocked
	if flow, ok := m.flowsByKey[key]; ok {
		flow.rxPackets.Add(1)
		flow.rxBytes.Add(uint64(packetLength))
		flow.lastSeenNano.Store(time.Now().UnixNano())
		flow.setEgressKind(egressKind)
		flow.setTrafficClass(metadata.TrafficClass)
		flow.enrichSCIONMetadata(metadata)
		return flow.snapshot(), false
	}

	// Create new flow
	id := m.nextID
	m.nextID++

	now := time.Now()
	tc := metadata.TrafficClass
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
		trafficClass:   tc,
		srcIA:          metadata.SrcIA,
		dstIA:          metadata.DstIA,
		createdAt:      now,
	}

	// Initialize atomic counters
	flow.rxPackets.Store(1)
	flow.rxBytes.Store(uint64(packetLength))
	flow.lastSeenNano.Store(now.UnixNano())

	// Incoming packet: the socket's local side is the packet destination.
	sockProto, sockSrc, sockDst := metadata.socketTuple()
	flow.initSocket(sockProto, sockDst, sockSrc)

	m.flowsByKey[key] = flow
	m.flowsByID[id] = flow

	log.Printf("[FLOW-DEBUG] [FlowManager] ObserveRx: NEW FLOW CREATED: id=%d egressKind='%s' class=%d proto=%d src=%s dst=%s scionDstIP=%s dstIA='%s'",
		id, egressKind, tc, metadata.Protocol, metadata.Source, metadata.Destination, metadata.SCIONDstIP, metadata.DstIA)

	snap := flow.snapshot()
	created = &snap
	return snap, true
}

// GetByID returns a snapshot of the flow with the given ID, or false if unknown.
func (m *Manager) GetByID(id ID) (Snapshot, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	flow, ok := m.flowsByID[id]
	if !ok {
		return Snapshot{}, false
	}
	return flow.snapshot(), true
}

// GetByMetadata looks up an existing flow by the canonical Key of a parsed
// packet (IP version, protocol and both endpoints, direction-independent).
// It never creates or updates a flow. Used by the translator's path override
// resolver (registered in Device.InitSCION via SetPathOverrideResolver) to find the
// manual override fingerprint for an outgoing packet.
func (m *Manager) GetByMetadata(metadata PacketMetadata) (Snapshot, bool) {
	key := newKey(metadata.IPVersion, metadata.Protocol, metadata.Source, metadata.Destination)
	m.mu.RLock()
	defer m.mu.RUnlock()
	flow, ok := m.flowsByKey[key]
	if !ok {
		return Snapshot{}, false
	}
	return flow.snapshot(), true
}

// GetByTuple is an alias for GetByMetadata.
func (m *Manager) GetByTuple(metadata PacketMetadata) (Snapshot, bool) {
	return m.GetByMetadata(metadata)
}

// Snapshot returns copies of all tracked flows sorted by ID. It is the data
// source for Device.FlowSnapshots and therefore for wgGetFlows / the flow list.
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
