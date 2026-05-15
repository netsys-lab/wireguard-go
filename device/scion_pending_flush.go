package device

import (
	"net"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"golang.org/x/net/ipv6"
)

func (device *Device) OnPathReady(src, dst addr.IA) {
	device.log.Verbosef("[SCION-PENDING] OnPathReady: src=%s dst=%s", src, dst)

	if device.pendingSCION == nil {
		device.log.Errorf("[SCION-PENDING] OnPathReady but pending queue nil")
		return
	}

	packets := device.pendingSCION.Pop(src, dst)
	if len(packets) == 0 {
		device.log.Verbosef("[SCION-PENDING] OnPathReady: no packets to flush src=%s dst=%s", src, dst)
		return
	}

	device.log.Verbosef("[SCION-PENDING] OnPathReady: flushing count=%d src=%s dst=%s", len(packets), src, dst)

	for _, p := range packets {
		device.flushOnePendingSCION(p)
	}
}

func (device *Device) flushOnePendingSCION(p pendingSCIONPacket) {
	device.log.Verbosef("[SCION-PENDING] retry packet: len=%d age=%s", len(p.packet), time.Since(p.created))

	if device.translator == nil {
		device.log.Errorf("[SCION-PENDING] translator nil while flushing")
		return
	}

	if len(p.packet) < 1 {
		device.log.Errorf("[SCION-PENDING] empty queued packet")
		return
	}

	switch p.packet[0] >> 4 {
	case 6:
		if len(p.packet) < ipv6.HeaderLen {
			device.log.Errorf("[SCION-PENDING] queued IPv6 packet too short len=%d", len(p.packet))
			return
		}

		dstIP := net.IP(p.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len])
		srcIP := net.IP(p.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len])

		newpkt, err := device.translator.ReadOutboundPacket(p.packet, dstIP, srcIP, p.hostPort, true)
		if err != nil {
			device.log.Errorf("[SCION-PENDING] retry translation failed: %v", err)
			return
		}

		device.log.Verbosef("[SCION-PENDING] retry translation success: outLen=%d", len(newpkt))

		peer := device.lookupPeerForPacket(newpkt)
		if peer == nil {
			device.log.Errorf("[SCION-PENDING] retry peer lookup failed")
			return
		}

		device.log.Verbosef("[SCION-PENDING] retry peer lookup success: peer=%v", peer)

		device.QueueOutboundPacket(peer, newpkt)

	default:
		device.log.Errorf("[SCION-PENDING] unsupported queued packet IP version=%d", p.packet[0]>>4)
	}
}

func (device *Device) QueueOutboundPacket(peer *Peer, pkt []byte) {
	if peer == nil {
		device.log.Errorf("[SCION-PENDING] QueueOutboundPacket called with nil peer")
		return
	}

	if !peer.isRunning.Load() {
		device.log.Errorf("[SCION-PENDING] peer not running while queueing packet")
		return
	}

	elem := device.NewOutboundElement()

	if len(pkt) > len(elem.buffer)-MessageTransportHeaderSize {
		device.log.Errorf("[SCION-PENDING] packet too large to queue: len=%d max=%d",
			len(pkt), len(elem.buffer)-MessageTransportHeaderSize)
		device.PutMessageBuffer(elem.buffer)
		device.PutOutboundElement(elem)
		return
	}

	copy(elem.buffer[MessageTransportHeaderSize:], pkt)
	elem.packet = elem.buffer[MessageTransportHeaderSize : MessageTransportHeaderSize+len(pkt)]

	elemsContainer := device.GetOutboundElementsContainer()
	elemsContainer.elems = append(elemsContainer.elems, elem)

	device.log.Verbosef("[SCION-PENDING] queueing retry packet into WG outbound: len=%d", len(pkt))

	peer.StagePackets(elemsContainer)
	peer.SendStagedPackets()

	device.log.Verbosef("[SCION-PENDING] retry packet queued into WG outbound")
}
