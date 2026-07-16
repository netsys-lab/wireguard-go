/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/ratelimiter"
	"golang.zx2c4.com/wireguard/rwcancel"
	daemon "golang.zx2c4.com/wireguard/translator/daemon"
	"golang.zx2c4.com/wireguard/translator/header_parsing"
	pathcache "golang.zx2c4.com/wireguard/translator/pathpool"
	"golang.zx2c4.com/wireguard/tun"
)

type Device struct {
	state struct {
		// state holds the device's state. It is accessed atomically.
		// Use the device.deviceState method to read it.
		// device.deviceState does not acquire the mutex, so it captures only a snapshot.
		// During state transitions, the state variable is updated before the device itself.
		// The state is thus either the current state of the device or
		// the intended future state of the device.
		// For example, while executing a call to Up, state will be deviceStateUp.
		// There is no guarantee that that intended future state of the device
		// will become the actual state; Up can fail.
		// The device can also change state multiple times between time of check and time of use.
		// Unsynchronized uses of state must therefore be advisory/best-effort only.
		state atomic.Uint32 // actually a deviceState, but typed uint32 for convenience
		// stopping blocks until all inputs to Device have been closed.
		stopping sync.WaitGroup
		// mu protects state changes.
		sync.Mutex
	}

	net struct {
		stopping sync.WaitGroup
		sync.RWMutex
		bind          conn.Bind // bind interface
		netlinkCancel *rwcancel.RWCancel
		port          uint16 // listening port
		fwmark        uint32 // mark value (0 = disabled)
		brokenRoaming bool
	}

	staticIdentity struct {
		sync.RWMutex
		privateKey NoisePrivateKey
		publicKey  NoisePublicKey
	}

	peers struct {
		sync.RWMutex // protects keyMap
		keyMap       map[NoisePublicKey]*Peer
	}

	rate struct {
		underLoadUntil atomic.Int64
		limiter        ratelimiter.Ratelimiter
	}

	allowedips    AllowedIPs
	indexTable    IndexTable
	cookieChecker CookieChecker

	pathPool   *pathcache.PathPool
	translator *header_parsing.Translator

	pool struct {
		inboundElementsContainer  *WaitPool
		outboundElementsContainer *WaitPool
		messageBuffers            *WaitPool
		inboundElements           *WaitPool
		outboundElements          *WaitPool
	}

	queue struct {
		encryption *outboundQueue
		decryption *inboundQueue
		handshake  *handshakeQueue
	}

	tun struct {
		device tun.Device
		mtu    atomic.Int32
	}

	ipcMutex     sync.RWMutex
	closed       chan struct{}
	log          *Logger
	scionLog     *SCIONLogger
	pendingSCION *PendingSCIONQueue

	// packetIDCounter is a monotonic counter for SCION packet correlation.
	// It is assigned only to SCION-mapped egress packets accepted from TUN
	// and is preserved through pending queue, flush, and WireGuard outbound.
	packetIDCounter atomic.Uint64
}

// deviceState represents the state of a Device.
// There are three states: down, up, closed.
// Transitions:
//
//	down -----+
//	  ↑↓      ↓
//	  up -> closed
type deviceState uint32

//go:generate go run golang.org/x/tools/cmd/stringer -type deviceState -trimprefix=deviceState
const (
	deviceStateDown deviceState = iota
	deviceStateUp
	deviceStateClosed
)

// deviceState returns device.state.state as a deviceState
// See those docs for how to interpret this value.
func (device *Device) deviceState() deviceState {
	return deviceState(device.state.state.Load())
}

// isClosed reports whether the device is closed (or is closing).
// See device.state.state comments for how to interpret this value.
func (device *Device) isClosed() bool {
	return device.deviceState() == deviceStateClosed
}

// isUp reports whether the device is up (or is attempting to come up).
// See device.state.state comments for how to interpret this value.
func (device *Device) isUp() bool {
	return device.deviceState() == deviceStateUp
}

// NextPacketID returns the next monotonic packet ID for SCION correlation.
// It is safe for concurrent use.
func (device *Device) NextPacketID() uint64 {
	return device.packetIDCounter.Add(1)
}

// Must hold device.peers.Lock()
func removePeerLocked(device *Device, peer *Peer, key NoisePublicKey) {
	// stop routing and processing of packets
	device.allowedips.RemoveByPeer(peer)
	peer.Stop()

	// remove from peer map
	delete(device.peers.keyMap, key)
}

// changeState attempts to change the device state to match want.
func (device *Device) changeState(want deviceState) (err error) {
	device.state.Lock()
	defer device.state.Unlock()
	old := device.deviceState()
	if old == deviceStateClosed {
		// once closed, always closed
		device.log.Verbosef("Interface closed, ignored requested state %s", want)
		return nil
	}
	switch want {
	case old:
		return nil
	case deviceStateUp:
		device.state.state.Store(uint32(deviceStateUp))
		err = device.upLocked()
		if err == nil {
			break
		}
		fallthrough // up failed; bring the device all the way back down
	case deviceStateDown:
		device.state.state.Store(uint32(deviceStateDown))
		errDown := device.downLocked()
		if err == nil {
			err = errDown
		}
	}
	device.log.Verbosef("Interface state was %s, requested %s, now %s", old, want, device.deviceState())
	return
}

// upLocked attempts to bring the device up and reports whether it succeeded.
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (device *Device) upLocked() error {
	if err := device.BindUpdate(); err != nil {
		device.log.Errorf("Unable to update bind: %v", err)
		return err
	}

	// The IPC set operation waits for peers to be created before calling Start() on them,
	// so if there's a concurrent IPC set request happening, we should wait for it to complete.
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Start()
		if peer.persistentKeepaliveInterval.Load() > 0 {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
	return nil
}

// downLocked attempts to bring the device down.
// The caller must hold device.state.mu and is responsible for updating device.state.state.
func (device *Device) downLocked() error {
	err := device.BindClose()
	if err != nil {
		device.log.Errorf("Bind close failed: %v", err)
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Stop()
	}
	device.peers.RUnlock()
	return err
}

func (device *Device) Up() error {
	return device.changeState(deviceStateUp)
}

func (device *Device) Down() error {
	return device.changeState(deviceStateDown)
}

func (device *Device) IsUnderLoad() bool {
	// check if currently under load
	now := time.Now()
	underLoad := len(device.queue.handshake.c) >= QueueHandshakeSize/8
	if underLoad {
		device.rate.underLoadUntil.Store(now.Add(UnderLoadAfterTime).UnixNano())
		return true
	}
	// check if recently under load
	return device.rate.underLoadUntil.Load() > now.UnixNano()
}

func (device *Device) SetPrivateKey(sk NoisePrivateKey) error {
	// lock required resources

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	if sk.Equals(device.staticIdentity.privateKey) {
		return nil
	}

	device.peers.Lock()
	defer device.peers.Unlock()

	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// remove peers with matching public keys

	publicKey := sk.publicKey()
	for key, peer := range device.peers.keyMap {
		if peer.handshake.remoteStatic.Equals(publicKey) {
			peer.handshake.mutex.RUnlock()
			removePeerLocked(device, peer, key)
			peer.handshake.mutex.RLock()
		}
	}

	// update key material

	device.staticIdentity.privateKey = sk
	device.staticIdentity.publicKey = publicKey
	device.cookieChecker.Init(publicKey)

	// do static-static DH pre-computations

	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(handshake.remoteStatic)
		expiredPeers = append(expiredPeers, peer)
	}

	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

func NewDevice(tunDevice tun.Device, bind conn.Bind, logger *Logger, scionConfig ScionDeviceConfig) *Device {
	device := new(Device)
	device.state.state.Store(uint32(deviceStateDown))
	device.closed = make(chan struct{})
	device.log = logger
	device.net.bind = bind
	device.tun.device = tunDevice

	// Initialize SCION logger before any SCION work so that init
	// messages can be routed through it.
	device.scionLog = NewSCIONLogger(logger)
	if scionConfig.LogConfig != nil {
		device.scionLog.SetConfig(*scionConfig.LogConfig)
	}

	// Emit effective configuration log once at startup.
	// Android-specific log config is applied later in InitSCION().
	LogEffectiveConfig(device.scionLog, "default", true)

	if scionConfig.Enabled {
		logger.Verbosef("SCION requested, deferred init")
	} else {
		logger.Verbosef("SCION disabled")
	}

	mtu, err := device.tun.device.MTU()
	if err != nil {
		device.log.Errorf("Trouble determining MTU, assuming default: %v", err)
		mtu = DefaultMTU
	}
	device.tun.mtu.Store(int32(mtu))
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.rate.limiter.Init()
	device.indexTable.Init()

	device.PopulatePools()

	// create queues

	device.queue.handshake = newHandshakeQueue()
	device.queue.encryption = newOutboundQueue()
	device.queue.decryption = newInboundQueue()

	// start workers

	cpus := runtime.NumCPU()
	device.state.stopping.Wait()
	device.queue.encryption.wg.Add(cpus) // One for each RoutineHandshake
	for i := 0; i < cpus; i++ {
		go device.RoutineEncryption(i + 1)
		go device.RoutineDecryption(i + 1)
		go device.RoutineHandshake(i + 1)
	}

	device.state.stopping.Add(1)      // RoutineReadFromTUN
	device.queue.encryption.wg.Add(1) // RoutineReadFromTUN
	go device.RoutineReadFromTUN()
	go device.RoutineTUNEventReader()

	return device
}

// We want the Bootstrapping for SCION to happen through the tunnel, so we need to create the device before we fetch and use it to create translator.
// So we need a Function for the device, that creates the translator and does all that afterwards, Would that be called from the main.go?
func (device *Device) InitSCION(scionConfig ScionDeviceConfig) error {
	if !scionConfig.Enabled {
		device.log.Verbosef("SCION disabled")
		return nil
	}

	if scionConfig.ConfigDir == "" {
		device.log.Errorf("SCION init failed: enabled but no config dir")
		return fmt.Errorf("SCION init failed: enabled but no config dir")
	}

	// Apply Android-provided log configuration if present.
	// This is called later than NewDevice(); the device already owns the TUN,
	// peers, translator, PathPool, and egress pipeline.
	if scionConfig.LogConfig != nil {
		device.scionLog.SetConfig(*scionConfig.LogConfig)
		LogEffectiveConfig(device.scionLog, "android-build-config", true)
	}

	localIA, err := loadLocalIAFromTopology(scionConfig.ConfigDir)
	if err != nil {
		device.log.Errorf("SCION init failed: could not load local IA from topology: %v", err)
		return fmt.Errorf("SCION init failed: could not load local IA from topology: %w", err)
	}

	brAddr, err := loadBRAddrFromTopology(scionConfig.ConfigDir)
	if err != nil {
		device.log.Errorf("SCION init failed: could not load BR address from topology: %w", err)
		return fmt.Errorf("SCION init failed: could not load BR address from topology: %w", err)
	}

	dispatchedPorts, err := loadDispatchedPortsFromTopology(scionConfig.ConfigDir)
	if err != nil {
		device.log.Errorf("SCION init failed: could not load dispatched_ports from topology: %w", err)
		return fmt.Errorf("SCION init failed: could not load dispatched_ports from topology: %w", err)
	}

	retriever, err := daemon.NewSciondRetriever(scionConfig.ConfigDir)
	if err != nil {
		device.log.Errorf("SCION init failed: %w", err)
		return fmt.Errorf("SCION init failed: %w", err)
	}

	pathPool := pathcache.NewPathPool(retriever)

	interfaceName := scionConfig.InterfaceName

	pendingSCION := NewPendingSCIONQueue(64, 40*time.Second)
	translator := header_parsing.NewTranslator(pathPool, localIA, brAddr, interfaceName)
	translator.SetDispatchedPorts(dispatchedPorts)

	// Set explicitly configured addresses (Android path).
	// These bypass net.InterfaceByName which is unavailable on Android.
	if scionConfig.LocalIPv4.IsValid() {
		translator.SetConfiguredIPv4(scionConfig.LocalIPv4)
	}
	if scionConfig.LocalIPv6.IsValid() {
		translator.SetConfiguredIPv6(scionConfig.LocalIPv6)
	}

	// Determine address source for structured logging.
	addressSource := "interface-lookup"
	if scionConfig.LocalIPv4.IsValid() || scionConfig.LocalIPv6.IsValid() {
		addressSource = "android-config"
	}
	device.log.Verbosef(
		"[SCION-INIT-CONFIG] interfaceName=%s localIPv4=%s localIPv6=%s addressSource=%s",
		interfaceName,
		scionConfig.LocalIPv4,
		scionConfig.LocalIPv6,
		addressSource,
	)
	device.log.Verbosef(
		"[SCION-INIT-CONFIG] dispatched_ports=%d-%d valid=%v localIA=%s brAddr=%s",
		dispatchedPorts.Start,
		dispatchedPorts.End,
		dispatchedPorts.Valid,
		localIA,
		brAddr,
	)

	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	if device.isClosed() {
		device.log.Errorf("SCION init failed: device is closed")
		return fmt.Errorf("SCION init failed: device is closed")
	}

	if device.translator != nil {
		device.log.Errorf("SCION init failed: translator already initialized")
		return fmt.Errorf("SCION init failed: translator already initialized")
	}

	device.pathPool = pathPool
	device.pendingSCION = pendingSCION
	pathPool.SetRefreshCallback(device.OnPathReady)
	device.translator = translator

	device.log.Verbosef(
		"SCION init success: configDir=%s localIA=%s brAddr=%s",
		scionConfig.ConfigDir,
		localIA,
		brAddr,
	)

	return nil
}

// BatchSize returns the BatchSize for the device as a whole which is the max of
// the bind batch size and the tun batch size. The batch size reported by device
// is the size used to construct memory pools, and is the allowed batch size for
// the lifetime of the device.
func (device *Device) BatchSize() int {
	size := device.net.bind.BatchSize()
	dSize := device.tun.device.BatchSize()
	if size < dSize {
		size = dSize
	}
	return size
}

func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()

	return device.peers.keyMap[pk]
}

func (device *Device) RemovePeer(key NoisePublicKey) {
	device.peers.Lock()
	defer device.peers.Unlock()
	// stop peer and remove from routing

	peer, ok := device.peers.keyMap[key]
	if ok {
		removePeerLocked(device, peer, key)
	}
}

func (device *Device) RemoveAllPeers() {
	device.peers.Lock()
	defer device.peers.Unlock()

	for key, peer := range device.peers.keyMap {
		removePeerLocked(device, peer, key)
	}

	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
}

func (device *Device) Close() {
	device.state.Lock()
	defer device.state.Unlock()
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	if device.isClosed() {
		return
	}
	device.state.state.Store(uint32(deviceStateClosed))
	device.log.Verbosef("Device closing")

	device.tun.device.Close()
	device.downLocked()

	// Remove peers before closing queues,
	// because peers assume that queues are active.
	device.RemoveAllPeers()

	// We kept a reference to the encryption and decryption queues,
	// in case we started any new peers that might write to them.
	// No new peers are coming; we are done with these queues.
	device.queue.encryption.wg.Done()
	device.queue.decryption.wg.Done()
	device.queue.handshake.wg.Done()
	device.state.stopping.Wait()

	device.rate.limiter.Close()

	device.log.Verbosef("Device closed")
	close(device.closed)
}

func (device *Device) Wait() chan struct{} {
	return device.closed
}

func (device *Device) SendKeepalivesToPeersWithCurrentKeypair() {
	if !device.isUp() {
		return
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.keypairs.RLock()
		sendKeepalive := peer.keypairs.current != nil && !peer.keypairs.current.created.Add(RejectAfterTime).Before(time.Now())
		peer.keypairs.RUnlock()
		if sendKeepalive {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
}

// closeBindLocked closes the device's net.bind.
// The caller must hold the net mutex.
func closeBindLocked(device *Device) error {
	var err error
	netc := &device.net
	if netc.netlinkCancel != nil {
		netc.netlinkCancel.Cancel()
	}
	if netc.bind != nil {
		err = netc.bind.Close()
	}
	netc.stopping.Wait()
	return err
}

func (device *Device) Bind() conn.Bind {
	device.net.Lock()
	defer device.net.Unlock()
	return device.net.bind
}

func (device *Device) BindSetMark(mark uint32) error {
	device.net.Lock()
	defer device.net.Unlock()

	// check if modified
	if device.net.fwmark == mark {
		return nil
	}

	// update fwmark on existing bind
	device.net.fwmark = mark
	if device.isUp() && device.net.bind != nil {
		if err := device.net.bind.SetMark(mark); err != nil {
			return err
		}
	}

	// clear cached source addresses
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	return nil
}

func (device *Device) BindUpdate() error {
	device.net.Lock()
	defer device.net.Unlock()

	// close existing sockets
	if err := closeBindLocked(device); err != nil {
		return err
	}

	// open new sockets
	if !device.isUp() {
		return nil
	}

	// bind to new port
	var err error
	var recvFns []conn.ReceiveFunc
	netc := &device.net

	recvFns, netc.port, err = netc.bind.Open(netc.port)
	if err != nil {
		netc.port = 0
		return err
	}

	netc.netlinkCancel, err = device.startRouteListener(netc.bind)
	if err != nil {
		netc.bind.Close()
		netc.port = 0
		return err
	}

	// set fwmark
	if netc.fwmark != 0 {
		err = netc.bind.SetMark(netc.fwmark)
		if err != nil {
			return err
		}
	}

	// clear cached source addresses
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	// start receiving routines
	device.net.stopping.Add(len(recvFns))
	device.queue.decryption.wg.Add(len(recvFns)) // each RoutineReceiveIncoming goroutine writes to device.queue.decryption
	device.queue.handshake.wg.Add(len(recvFns))  // each RoutineReceiveIncoming goroutine writes to device.queue.handshake
	batchSize := netc.bind.BatchSize()
	for _, fn := range recvFns {
		go device.RoutineReceiveIncoming(batchSize, fn)
	}

	device.log.Verbosef("UDP bind has been updated")
	return nil
}

func (device *Device) BindClose() error {
	device.net.Lock()
	err := closeBindLocked(device)
	device.net.Unlock()
	return err
}

func (device *Device) lookupPeerForPacket(packet []byte) *Peer {
	if len(packet) < 1 {
		return nil
	}

	version := packet[0] >> 4
	var dstIP []byte

	switch version {
	case 4:
		if len(packet) < 20 {
			return nil
		}
		dstIP = packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]
	case 6:
		if len(packet) < 40 {
			return nil
		}
		dstIP = packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
	default:
		return nil
	}

	device.log.Verbosef("[LOOKUP] Looking up peer for IP: %s", net.IP(dstIP).String())
	peer := device.allowedips.Lookup(dstIP)
	if peer != nil {
		device.log.Verbosef("[LOOKUP] Found peer for IP %s", net.IP(dstIP).String())
	} else {
		device.log.Verbosef("[LOOKUP] No peer found for IP %s", net.IP(dstIP).String())
	}
	return peer
}
