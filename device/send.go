/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	//"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/flow"
	"golang.zx2c4.com/wireguard/scionlog"
	"golang.zx2c4.com/wireguard/translator/header_parsing"
	"golang.zx2c4.com/wireguard/translator/pathpool"
	"golang.zx2c4.com/wireguard/tun"
)

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The functions in this file occur (roughly) in the order in
 * which the packets are processed.
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)
 */

type QueueOutboundElement struct {
	buffer   *[MaxMessageSize]byte // slice holding the packet data
	packet   []byte                // slice of "buffer" (always!)
	nonce    uint64                // nonce for encryption
	keypair  *Keypair              // keypair for encryption
	peer     *Peer                 // related peer
	PacketID uint64                // SCION packet correlation ID (0 = not traced)
}

type QueueOutboundElementsContainer struct {
	sync.Mutex
	elems []*QueueOutboundElement
}

func (device *Device) NewOutboundElement() *QueueOutboundElement {
	elem := device.GetOutboundElement()
	elem.buffer = device.GetMessageBuffer()
	elem.nonce = 0
	// keypair and peer were cleared (if necessary) by clearPointers.
	return elem
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueOutboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.peer = nil
	elem.PacketID = 0
}

/* Queues a keepalive if no packets are queued for peer
 */
func (peer *Peer) SendKeepalive() {
	if len(peer.queue.staged) == 0 && peer.isRunning.Load() {
		elem := peer.device.NewOutboundElement()
		elemsContainer := peer.device.GetOutboundElementsContainer()
		elemsContainer.elems = append(elemsContainer.elems, elem)
		select {
		case peer.queue.staged <- elemsContainer:
			peer.device.log.Verbosef("%v - Sending keepalive packet", peer)
		default:
			peer.device.PutMessageBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
			peer.device.PutOutboundElementsContainer(elemsContainer)
		}
	}
	peer.SendStagedPackets()
}

func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	if !isRetry {
		peer.timers.handshakeAttempts.Store(0)
	}

	peer.handshake.mutex.RLock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.RUnlock()
		return nil
	}
	peer.handshake.mutex.RUnlock()

	peer.handshake.mutex.Lock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.Unlock()
		return nil
	}
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake initiation", peer)

	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create initiation message: %v", peer, err)
		return err
	}

	var buf [MessageInitiationSize]byte
	writer := bytes.NewBuffer(buf[:0])
	binary.Write(writer, binary.LittleEndian, msg)
	packet := writer.Bytes()
	peer.cookieGenerator.AddMacs(packet)

	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake initiation: %v", peer, err)
	}
	peer.timersHandshakeInitiated()

	return err
}

func (peer *Peer) SendHandshakeResponse() error {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake response", peer)

	response, err := peer.device.CreateMessageResponse(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create response message: %v", peer, err)
		return err
	}

	var buf [MessageResponseSize]byte
	writer := bytes.NewBuffer(buf[:0])
	binary.Write(writer, binary.LittleEndian, response)
	packet := writer.Bytes()
	peer.cookieGenerator.AddMacs(packet)

	err = peer.BeginSymmetricSession()
	if err != nil {
		peer.device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
		return err
	}

	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	// TODO: allocation could be avoided
	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake response: %v", peer, err)
	}
	return err
}

func (device *Device) SendHandshakeCookie(initiatingElem *QueueHandshakeElement) error {
	device.log.Verbosef("Sending cookie response for denied handshake message for %v", initiatingElem.endpoint.DstToString())

	sender := binary.LittleEndian.Uint32(initiatingElem.packet[4:8])
	reply, err := device.cookieChecker.CreateReply(initiatingElem.packet, sender, initiatingElem.endpoint.DstToBytes())
	if err != nil {
		device.log.Errorf("Failed to create cookie reply: %v", err)
		return err
	}

	var buf [MessageCookieReplySize]byte
	writer := bytes.NewBuffer(buf[:0])
	binary.Write(writer, binary.LittleEndian, reply)
	// TODO: allocation could be avoided
	device.net.bind.Send([][]byte{writer.Bytes()}, initiatingElem.endpoint)
	return nil
}

func (peer *Peer) keepKeyFreshSending() {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return
	}
	nonce := keypair.sendNonce.Load()
	if nonce > RekeyAfterMessages || (keypair.isInitiator && time.Since(keypair.created) > RekeyAfterTime) {
		peer.SendHandshakeInitiation(false)
	}
}

func (device *Device) RoutineReadFromTUN() {
	defer func() {
		device.log.Verbosef("Routine: TUN reader - stopped")
		device.state.stopping.Done()
		device.queue.encryption.wg.Done()
	}()

	device.log.Verbosef("Routine: TUN reader - started")

	var (
		batchSize   = device.BatchSize()
		readErr     error
		elems       = make([]*QueueOutboundElement, batchSize)
		bufs        = make([][]byte, batchSize)
		elemsByPeer = make(map[*Peer]*QueueOutboundElementsContainer, batchSize)
		count       = 0
		sizes       = make([]int, batchSize)
		offset      = MessageTransportHeaderSize
	)

	for i := range elems {
		elems[i] = device.NewOutboundElement()
		bufs[i] = elems[i].buffer[:]
	}

	defer func() {
		for _, elem := range elems {
			if elem != nil {
				device.PutMessageBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
		}
	}()

	for {
		// read packets from TUN
		count, readErr = device.tun.device.Read(bufs, sizes, offset)

		//write byte length into sizes[i]
		for i := 0; i < count; i++ {
			if sizes[i] < 1 {
				continue
			}

			elem := elems[i]
			//create a window elem.packet over just the valid bytes
			pkt := bufs[i][offset : offset+sizes[i]]

			elem.packet = pkt

			// lookup peer
			var peer *Peer
			packetID := device.NextPacketID()
			device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=accepted bytes=%d", packetID, len(pkt))
			switch elem.packet[0] >> 4 {
			case 4:
				if len(elem.packet) < ipv4.HeaderLen {
					continue
				}
				dst := elem.packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]
				peer = device.allowedips.Lookup(dst)

				if device.flowManager != nil {
					if md, err := flow.ParsePacketMetadata(pkt); err == nil {
						if snap, created := device.flowManager.ObserveTx(md, len(pkt), "ip"); created {
							device.log.Verbosef(
								"Flow created: id=%d egress=%s protocol=%s endpoint_a=%s endpoint_b=%s tx_packets=%d tx_bytes=%d",
								snap.ID, snap.EgressKind, snap.ProtocolName(),
								snap.EndpointA, snap.EndpointB,
								snap.TxPackets, snap.TxBytes,
							)
						}
					} else {
						device.scionLog.Debugf(scionlog.ComponentFlow, "[FLOW] event=parse-failed egress=ip err=%v packetLen=%d ipVersion=4", err, len(pkt))
					}
				}

			case 6:
				if len(elem.packet) < ipv6.HeaderLen {
					continue
				}
				dst := elem.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]

				dstIP := net.IP(dst)
				peer = device.allowedips.Lookup(dst)
				if device.translator != nil && header_parsing.IsSCIONMapped(dstIP) {
					if peer == nil {
						device.scionLog.Errorf(scionlog.ComponentEgressLifecycle,
							"[SCION-EGRESS] packetId=%d event=peer-lookup-failed lookupStage=before-translation lookupDst=%s",
							packetID, dstIP.String())
						continue
					}
					device.scionLog.Debugf(scionlog.ComponentEgressLifecycle,
						"[SCION-EGRESS] packetId=%d event=peer-selected-original-dst lookupDst=%s",
						packetID, dstIP.String())

					//Flow Manager with Scion call
					if device.flowManager != nil {
						if md, err := flow.ParsePacketMetadata(pkt); err == nil {
							var scionSrcIA, scionDstIA addr.IA
							mapped, mapErr := device.translator.MappedDestinationFor(dstIP)
							if mapErr == nil {
								md.SrcIA = mapped.SrcIA.String()
								md.DstIA = mapped.DstIA.String()
								md.SCIONDstIP = mapped.Host
								scionSrcIA = mapped.SrcIA
								scionDstIA = mapped.DstIA
							}
							snap, created := device.flowManager.ObserveTx(md, len(pkt), "scion")
							if created {
								device.log.Verbosef(
									"Flow created: id=%d egress=%s protocol=%s endpoint_a=%s endpoint_b=%s tx_packets=%d tx_bytes=%d",
									snap.ID, snap.EgressKind, snap.ProtocolName(),
									snap.EndpointA, snap.EndpointB,
									snap.TxPackets, snap.TxBytes,
								)
							}
							if mapErr == nil {
								device.rememberSCIONEgress(snap.ID, scionSrcIA, scionDstIA)
							}
						} else {
							device.scionLog.Debugf(scionlog.ComponentFlow, "[FLOW] event=parse-failed egress=scion err=%v packetLen=%d ipVersion=6", err, len(pkt))
						}
					}

					srcIP := net.IP(pkt[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len])
					hostPort := 35000
					start := time.Now()
					newpkt, err := device.translator.ReadOutboundPacket(pkt, dstIP, srcIP, hostPort, true)
					translateDur := time.Since(start)
					if err != nil {
						if errors.Is(err, pathpool.ErrPathPending) {
							mapped, iaErr := device.translator.MappedDestinationFor(dstIP)
							if iaErr != nil {
								device.scionLog.Errorf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=translation-failed reason=ia-extract err=%v", packetID, iaErr)
								continue
							}

							if device.pendingSCION == nil {
								device.scionLog.Errorf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=translation-failed reason=pending-nil src=%s dst=%s", packetID, mapped.SrcIA, mapped.DstIA)
								continue
							}

							device.pendingSCION.Enqueue(mapped.SrcIA, mapped.DstIA, pkt, true, hostPort, packetID)
							device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=queued-pending src=%s dst=%s bytes=%d", packetID, mapped.SrcIA, mapped.DstIA, len(pkt))
							continue
						}

						device.scionLog.Errorf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=translation-failed duration=%v err=%v", packetID, translateDur, err)
						continue
					}
					elem.PacketID = packetID

					elem.packet = newpkt
					sizes[i] = len(newpkt)
					device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=outer-built bytes=%d duration=%v", packetID, len(newpkt), translateDur)
				} else {
					// Not SCION-mapped - normal lookup
					peer = device.allowedips.Lookup(dst)

					//Flow manager if Ipv6 and not scion
					if device.flowManager != nil {
						if md, err := flow.ParsePacketMetadata(pkt); err == nil {
							if snap, created := device.flowManager.ObserveTx(md, len(pkt), "ip"); created {
								device.log.Verbosef(
									"Flow created: id=%d egress=%s protocol=%s endpoint_a=%s endpoint_b=%s tx_packets=%d tx_bytes=%d",
									snap.ID, snap.EgressKind, snap.ProtocolName(),
									snap.EndpointA, snap.EndpointB,
									snap.TxPackets, snap.TxBytes,
								)
							}
						} else {
							device.scionLog.Debugf(scionlog.ComponentFlow, "[FLOW] event=parse-failed egress=ip err=%v packetLen=%d ipVersion=6", err, len(pkt))
						}
					}

				}

			default:
				device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=accepted proto=%d", packetID, elem.packet[0]>>4)

				//Flow Manager Kind Unknow if not v6 or v4
				if device.flowManager != nil {
					if md, err := flow.ParsePacketMetadata(pkt); err == nil {
						if snap, created := device.flowManager.ObserveTx(md, len(pkt), "unknown"); created {
							device.log.Verbosef(
								"Flow created: id=%d egress=%s protocol=%s endpoint_a=%s endpoint_b=%s tx_packets=%d tx_bytes=%d",
								snap.ID, snap.EgressKind, snap.ProtocolName(),
								snap.EndpointA, snap.EndpointB,
								snap.TxPackets, snap.TxBytes,
							)
						}
					} else {
						device.scionLog.Debugf(scionlog.ComponentFlow, "[FLOW] event=parse-failed egress=unknown err=%v packetLen=%d ipVersion=%d", err, len(pkt), pkt[0]>>4)
					}
				}

				continue
			}

			if peer == nil {
				device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=peer-lookup-failed", packetID)
				continue
			}
			device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=peer-selected", packetID)
			elemsForPeer, ok := elemsByPeer[peer]
			if !ok {
				elemsForPeer = device.GetOutboundElementsContainer()
				elemsByPeer[peer] = elemsForPeer
			}
			elemsForPeer.elems = append(elemsForPeer.elems, elem)
			elems[i] = device.NewOutboundElement()
			bufs[i] = elems[i].buffer[:]
		}

		for peer, elemsForPeer := range elemsByPeer {
			if peer.isRunning.Load() {
				for _, elem := range elemsForPeer.elems {
					if elem.PacketID != 0 {
						device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=queued-for-encryption", elem.PacketID)
					}
				}
				peer.StagePackets(elemsForPeer)
				peer.SendStagedPackets()
			} else {
				for _, elem := range elemsForPeer.elems {
					device.PutMessageBuffer(elem.buffer)
					device.PutOutboundElement(elem)
				}
				device.PutOutboundElementsContainer(elemsForPeer)
			}
			delete(elemsByPeer, peer)
		}

		if readErr != nil {
			if errors.Is(readErr, tun.ErrTooManySegments) {
				// TODO: record stat for this
				// This will happen if MSS is surprisingly small (< 576)
				// coincident with reasonably high throughput.
				device.log.Verbosef("Dropped some packets from multi-segment read: %v", readErr)
				continue
			}
			if !device.isClosed() {
				if !errors.Is(readErr, os.ErrClosed) {
					device.log.Errorf("Failed to read packet from TUN device: %v", readErr)
				}
				go device.Close()
			}
			return
		}
	}
}

/*
func dummy_translation(b []byte, ipv int) {
	fmt.Println("Dummy translation called")
	switch ipv {
	case 4:
		header, err := ipv4.ParseHeader(b)
		if err != nil {
			fmt.Println("Error parsing IPv4 header:", err)
			return
		}
		originalFlags := header.Flags
		fmt.Println("IPv4 original flags:", originalFlags)
		header.Flags |= ipv4.DontFragment
		hdrBytes, _ := header.Marshal()
		copy(b[:len(hdrBytes)], hdrBytes)

	case 6:
		header, err := ipv6.ParseHeader(b)
		if err != nil {
			fmt.Println("Error parsing IPv6 header:", err)
			return
		}
		originalTC := header.TrafficClass
		fmt.Println("IPv6 original TrafficClass:", originalTC)
		b[1] = (b[1] & 0xF0) | ((b[1] ^ 0x01) & 0x0F)

	}

}
*/

func (peer *Peer) StagePackets(elems *QueueOutboundElementsContainer) {
	for {
		select {
		case peer.queue.staged <- elems:
			return
		default:
		}
		select {
		case tooOld := <-peer.queue.staged:
			for _, elem := range tooOld.elems {
				peer.device.PutMessageBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(tooOld)
		default:
		}
	}
}

func (peer *Peer) SendStagedPackets() {
top:
	if len(peer.queue.staged) == 0 || !peer.device.isUp() {
		return
	}

	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || time.Since(keypair.created) >= RejectAfterTime {
		peer.SendHandshakeInitiation(false)
		return
	}

	for {
		var elemsContainerOOO *QueueOutboundElementsContainer
		select {
		case elemsContainer := <-peer.queue.staged:
			i := 0
			for _, elem := range elemsContainer.elems {
				elem.peer = peer
				elem.nonce = keypair.sendNonce.Add(1) - 1
				if elem.nonce >= RejectAfterMessages {
					keypair.sendNonce.Store(RejectAfterMessages)
					if elemsContainerOOO == nil {
						elemsContainerOOO = peer.device.GetOutboundElementsContainer()
					}
					elemsContainerOOO.elems = append(elemsContainerOOO.elems, elem)
					continue
				} else {
					elemsContainer.elems[i] = elem
					i++
				}

				elem.keypair = keypair
			}
			elemsContainer.Lock()
			elemsContainer.elems = elemsContainer.elems[:i]

			if elemsContainerOOO != nil {
				peer.StagePackets(elemsContainerOOO) // XXX: Out of order, but we can't front-load go chans
			}

			if len(elemsContainer.elems) == 0 {
				peer.device.PutOutboundElementsContainer(elemsContainer)
				goto top
			}

			// add to parallel and sequential queue
			if peer.isRunning.Load() {
				peer.queue.outbound.c <- elemsContainer
				peer.device.queue.encryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					peer.device.PutMessageBuffer(elem.buffer)
					peer.device.PutOutboundElement(elem)
				}
				peer.device.PutOutboundElementsContainer(elemsContainer)
			}

			if elemsContainerOOO != nil {
				goto top
			}
		default:
			return
		}
	}
}

func (peer *Peer) FlushStagedPackets() {
	for {
		select {
		case elemsContainer := <-peer.queue.staged:
			for _, elem := range elemsContainer.elems {
				peer.device.PutMessageBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(elemsContainer)
		default:
			return
		}
	}
}

func calculatePaddingSize(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		return ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1)) - lastUnit
	}
	if lastUnit > mtu {
		lastUnit %= mtu
	}
	paddedSize := ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1))
	if paddedSize > mtu {
		paddedSize = mtu
	}
	return paddedSize - lastUnit
}

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
func (device *Device) RoutineEncryption(id int) {
	var paddingZeros [PaddingMultiple]byte
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: encryption worker %d - stopped", id)
	device.log.Verbosef("Routine: encryption worker %d - started", id)

	for elemsContainer := range device.queue.encryption.c {
		for _, elem := range elemsContainer.elems {
			// populate header fields
			header := elem.buffer[:MessageTransportHeaderSize]

			fieldType := header[0:4]
			fieldReceiver := header[4:8]
			fieldNonce := header[8:16]

			binary.LittleEndian.PutUint32(fieldType, MessageTransportType)
			binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex)
			binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

			// pad content to multiple of 16
			paddingSize := calculatePaddingSize(len(elem.packet), int(device.tun.mtu.Load()))
			elem.packet = append(elem.packet, paddingZeros[:paddingSize]...)

			// encrypt content and release to consumer

			binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)
			elem.packet = elem.keypair.send.Seal(
				header,
				nonce[:],
				elem.packet,
				nil,
			)
		}
		// Log encrypted event for traced packets
		var encFirstID, encLastID uint64
		var encTracedCount int
		for _, elem := range elemsContainer.elems {
			if elem.PacketID != 0 {
				encTracedCount++
				if encFirstID == 0 {
					encFirstID = elem.PacketID
				}
				encLastID = elem.PacketID
			}
		}
		if encFirstID != 0 {
			device.scionLog.Tracef(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=encrypted tracedPackets=%d", encFirstID, encTracedCount)
			if encLastID != encFirstID {
				device.scionLog.Tracef(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=encrypted tracedPackets=%d", encLastID, encTracedCount)
			}
		}
		elemsContainer.Unlock()
	}
}

func (peer *Peer) RoutineSequentialSender(maxBatchSize int) {
	device := peer.device
	defer func() {
		defer device.log.Verbosef("%v - Routine: sequential sender - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential sender - started", peer)

	bufs := make([][]byte, 0, maxBatchSize)

	for elemsContainer := range peer.queue.outbound.c {
		bufs = bufs[:0]
		if elemsContainer == nil {
			return
		}
		if !peer.isRunning.Load() {
			// peer has been stopped; return re-usable elems to the shared pool.
			// This is an optimization only. It is possible for the peer to be stopped
			// immediately after this check, in which case, elem will get processed.
			// The timers and SendBuffers code are resilient to a few stragglers.
			// TODO: rework peer shutdown order to ensure
			// that we never accidentally keep timers alive longer than necessary.
			elemsContainer.Lock()
			for _, elem := range elemsContainer.elems {
				device.PutMessageBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
			device.PutOutboundElementsContainer(elemsContainer)
			continue
		}
		dataSent := false
		elemsContainer.Lock()
		for _, elem := range elemsContainer.elems {
			if len(elem.packet) != MessageKeepaliveSize {
				dataSent = true
			}
			bufs = append(bufs, elem.packet)
		}

		// Log batch with bounded packet IDs for traced packets
		var firstID, lastID uint64
		var tracedCount int
		for _, elem := range elemsContainer.elems {
			if elem.PacketID != 0 {
				tracedCount++
				if firstID == 0 {
					firstID = elem.PacketID
				}
				lastID = elem.PacketID
			}
		}
		if firstID != 0 {
			totalBytes := 0
			for _, b := range bufs {
				totalBytes += len(b)
			}
			device.scionLog.Debugf(scionlog.ComponentEgressLifecycle,
				"[SCION-EGRESS] event=socket-write-start peer=%s firstPacketId=%d lastPacketId=%d tracedPackets=%d buffers=%d totalBytes=%d",
				peer, firstID, lastID, tracedCount, len(bufs), totalBytes)
		}

		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()

		err := peer.SendBuffers(bufs)
		if dataSent {
			peer.timersDataSent()
		}
		// Log socket success/failure
		if firstID != 0 {
			if err != nil {
				device.scionLog.Errorf(scionlog.ComponentEgressLifecycle,
					"[SCION-EGRESS] event=socket-write-failed peer=%s firstPacketId=%d tracedPackets=%d err=%v",
					peer, firstID, tracedCount, err)
			} else {
				totalBytes := 0
				for _, b := range bufs {
					totalBytes += len(b)
				}
				device.scionLog.Tracef(scionlog.ComponentEgressLifecycle,
					"[SCION-EGRESS] event=socket-write-success peer=%s firstPacketId=%d lastPacketId=%d tracedPackets=%d buffers=%d totalBytes=%d",
					peer, firstID, lastID, tracedCount, len(bufs), totalBytes)
			}
		}
		for _, elem := range elemsContainer.elems {
			device.PutMessageBuffer(elem.buffer)
			device.PutOutboundElement(elem)
		}
		device.PutOutboundElementsContainer(elemsContainer)
		if err != nil {
			var errGSO conn.ErrUDPGSODisabled
			if errors.As(err, &errGSO) {
				device.log.Verbosef(err.Error())
				err = errGSO.RetryErr
			}
		}
		if err != nil {
			device.log.Errorf("%v - Failed to send data packets: %v", peer, err)
			continue
		}

		peer.keepKeyFreshSending()
	}
}
