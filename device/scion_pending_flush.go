package device

import (
	"net"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/scionlog"
)

/*
Handles retrying queued SCION packets after paths become available.

When the PathPool finishes an async refresh, Device.OnPathReady is called.

This file pops pending packets for that IA pair, translates them again using the refreshed path cache,
performs peer lookup, and injects them into the normal WireGuard outbound pipeline.

This keeps path fetching asynchronous while still preserving packets that
arrived during a cache miss.
*/

func (device *Device) OnPathReady(src, dst addr.IA) {
	flushStart := time.Now()

	if device.pendingSCION == nil {
		device.scionLog.Errorf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] event=flushing reason=nil-queue src=%s dst=%s", src, dst)
		return
	}

	packets := device.pendingSCION.Pop(src, dst)
	if len(packets) == 0 {
		device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] event=flushing reason=no-packets src=%s dst=%s", src, dst)
		return
	}

	device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] event=flushing count=%d src=%s dst=%s", len(packets), src, dst)

	for _, p := range packets {
		device.flushOnePendingSCION(p)
	}

	flushDur := time.Since(flushStart)
	device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] event=flush-complete count=%d src=%s dst=%s elapsedMs=%d",
		len(packets), src, dst, flushDur.Milliseconds())
}

func (device *Device) flushOnePendingSCION(p pendingSCIONPacket) {
	device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=flushing age=%s", p.packetID, time.Since(p.created))

	if device.translator == nil {
		device.scionLog.Errorf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=translation-failed reason=translator-nil", p.packetID)
		return
	}

	if len(p.packet) < 1 {
		device.scionLog.Errorf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=translation-failed reason=empty-packet", p.packetID)
		return
	}

	switch p.packet[0] >> 4 {
	case 6:
		if len(p.packet) < ipv6.HeaderLen {
			device.scionLog.Errorf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=translation-failed reason=packet-too-short len=%d", p.packetID, len(p.packet))
			return
		}

		dstIP := net.IP(p.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len])
		srcIP := net.IP(p.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len])

		peer := device.allowedips.Lookup(p.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len])
		if peer == nil {
			device.scionLog.Errorf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=peer-lookup-failed lookupStage=before-translation lookupDst=%s", p.packetID, dstIP.String())
			return
		}
		device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=peer-selected-original-dst lookupDst=%s", p.packetID, dstIP.String())

		start := time.Now()
		newpkt, err := device.translator.ReadOutboundPacket(p.packet, dstIP, srcIP, p.hostPort, true)
		translateDur := time.Since(start)
		if err != nil {
			device.scionLog.Errorf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=translation-failed duration=%v err=%v", p.packetID, translateDur, err)
			return
		}

		device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=outer-built bytes=%d duration=%v", p.packetID, len(newpkt), translateDur)

		device.scionLog.Debugf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=queued-for-encryption", p.packetID)

		device.QueueOutboundPacket(peer, newpkt, p.packetID)

	default:
		device.scionLog.Errorf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=translation-failed reason=unsupported-ip-version version=%d", p.packetID, p.packet[0]>>4)
	}
}

func (device *Device) QueueOutboundPacket(peer *Peer, pkt []byte, packetID uint64) {
	if peer == nil {
		device.scionLog.Errorf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=peer-lookup-failed reason=nil-peer", packetID)
		return
	}

	if !peer.isRunning.Load() {
		device.scionLog.Errorf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=peer-lookup-failed reason=peer-not-running", packetID)
		return
	}

	elem := device.NewOutboundElement()

	if len(pkt) > len(elem.buffer)-MessageTransportHeaderSize {
		device.scionLog.Errorf(scionlog.ComponentEgressLifecycle, "[SCION-EGRESS] packetId=%d event=queued-for-encryption-failed reason=packet-too-large len=%d max=%d",
			packetID, len(pkt), len(elem.buffer)-MessageTransportHeaderSize)
		device.PutMessageBuffer(elem.buffer)
		device.PutOutboundElement(elem)
		return
	}

	copy(elem.buffer[MessageTransportHeaderSize:], pkt)
	elem.packet = elem.buffer[MessageTransportHeaderSize : MessageTransportHeaderSize+len(pkt)]
	elem.PacketID = packetID

	elemsContainer := device.GetOutboundElementsContainer()
	elemsContainer.elems = append(elemsContainer.elems, elem)

	peer.StagePackets(elemsContainer)
	peer.SendStagedPackets()
}
