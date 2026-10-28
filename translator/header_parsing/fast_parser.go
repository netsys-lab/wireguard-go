package header_parsing

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/slayers"
)

var (
	// ErrPacketTooShort indicates the packet buffer is shorter than the minimum IPv6 header (40 bytes).
	ErrPacketTooShort = errors.New("packet too short for IPv6")
	// ErrNotIPv6 indicates the IP version nibble is not 6.
	ErrNotIPv6 = errors.New("not an IPv6 packet")
)

// Sync pools for reusable layer structs to achieve 0 heap allocations in the hot path.
var (
	tcpLayerPool = sync.Pool{
		New: func() any {
			t := &layers.TCP{}
			t.Options = make([]layers.TCPOption, 0, 8)
			return t
		},
	}
	slayersUDPPool = sync.Pool{
		New: func() any {
			return &slayers.UDP{}
		},
	}
)

func getPooledTCP() *layers.TCP {
	tcp := tcpLayerPool.Get().(*layers.TCP)
	opts := tcp.Options[:0]
	*tcp = layers.TCP{}
	tcp.Options = opts
	return tcp
}

func putPooledTCP(t *layers.TCP) {
	if t != nil {
		t.Options = t.Options[:0]
		t.Padding = nil
		t.Payload = nil
		t.Contents = nil
		t.BaseLayer = layers.BaseLayer{}
		tcpLayerPool.Put(t)
	}
}

func getPooledUDP() *slayers.UDP {
	u := slayersUDPPool.Get().(*slayers.UDP)
	*u = slayers.UDP{}
	return u
}

func putPooledUDP(u *slayers.UDP) {
	if u != nil {
		*u = slayers.UDP{}
		slayersUDPPool.Put(u)
	}
}

// FastIPv6Header contains decoded IPv6 base header fields extracted via fixed byte offsets (0 heap allocations).
type FastIPv6Header struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   layers.IPProtocol
	HopLimit     uint8
	SrcIP        net.IP
	DstIP        net.IP
}

// FastParsedPacket holds the parsed packet components.
// For standard IPv6 TCP and UDP traffic (without extension headers), it represents the zero-allocation fast-path.
// For packets carrying IPv6 extension headers or rare/unsupported protocols, it falls back to gopacket.Packet.
type FastParsedPacket struct {
	IPv6 FastIPv6Header

	L4Protocol layers.IPProtocol
	SrcPort    uint16
	DstPort    uint16
	Payload    []byte

	TCP *layers.TCP
	UDP *slayers.UDP

	IsFastPath     bool
	FallbackPacket gopacket.Packet
}

// Release returns any pooled layer structs back to their respective sync.Pools.
// It is safe to call even if the packet used the fallback path.
func (p *FastParsedPacket) Release() {
	if p.TCP != nil {
		putPooledTCP(p.TCP)
		p.TCP = nil
	}
	if p.UDP != nil {
		putPooledUDP(p.UDP)
		p.UDP = nil
	}
}

// FlowKey extracts or derives the 5-tuple for flow-path caching with 0 heap allocations.
func (p *FastParsedPacket) FlowKey(pktData []byte) (FlowKey, bool) {
	if p.IsFastPath {
		if len(p.IPv6.SrcIP) < 16 || len(p.IPv6.DstIP) < 16 {
			return FlowKey{}, false
		}
		srcAddr := netip.AddrFrom16([16]byte(p.IPv6.SrcIP))
		dstAddr := netip.AddrFrom16([16]byte(p.IPv6.DstIP))
		return FlowKey{
			SrcAddr: srcAddr,
			DstAddr: dstAddr,
			SrcPort: p.SrcPort,
			DstPort: p.DstPort,
			Proto:   uint8(p.L4Protocol),
		}, true
	}
	return ExtractFlowKey(pktData)
}

// ParseEgressPacket inspects pktData and parses IPv6 and standard L4 (TCP/UDP) headers
// using fixed byte offsets without dynamic heap allocations.
// If the packet contains IPv6 extension headers or rare protocols, it falls back to gopacket.NewPacket.
func ParseEgressPacket(pktData []byte) (FastParsedPacket, error) {
	if len(pktData) < 40 {
		return FastParsedPacket{}, ErrPacketTooShort
	}

	version := pktData[0] >> 4
	if version != 6 {
		return FastParsedPacket{}, ErrNotIPv6
	}

	ip6Hdr := FastIPv6Header{
		Version:      6,
		TrafficClass: uint8((binary.BigEndian.Uint16(pktData[0:2]) >> 4) & 0xFF),
		FlowLabel:    binary.BigEndian.Uint32(pktData[0:4]) & 0x000FFFFF,
		PayloadLen:   binary.BigEndian.Uint16(pktData[4:6]),
		NextHeader:   layers.IPProtocol(pktData[6]),
		HopLimit:     pktData[7],
		SrcIP:        net.IP(pktData[8:24]),
		DstIP:        net.IP(pktData[24:40]),
	}

	p := FastParsedPacket{
		IPv6:       ip6Hdr,
		L4Protocol: ip6Hdr.NextHeader,
	}

	switch ip6Hdr.NextHeader {
	case layers.IPProtocolTCP:
		if len(pktData) >= 60 { // 40 (IPv6) + 20 (min TCP)
			dataOffset := pktData[52] >> 4
			if dataOffset >= 5 {
				tcpHdrLen := int(dataOffset) * 4
				if len(pktData) >= 40+tcpHdrLen {
					tcp := getPooledTCP()
					fastParseTCP(pktData[40:], dataOffset, tcpHdrLen, tcp)

					p.IsFastPath = true
					p.TCP = tcp
					p.SrcPort = uint16(tcp.SrcPort)
					p.DstPort = uint16(tcp.DstPort)

					payloadStart := 40 + tcpHdrLen
					payloadEnd := len(pktData)
					if ip6Hdr.PayloadLen > 0 && 40+int(ip6Hdr.PayloadLen) <= len(pktData) {
						payloadEnd = 40 + int(ip6Hdr.PayloadLen)
					}
					if payloadEnd > payloadStart {
						p.Payload = pktData[payloadStart:payloadEnd]
						tcp.Payload = p.Payload
					}
					return p, nil
				}
			}
		}

	case layers.IPProtocolUDP:
		if len(pktData) >= 48 { // 40 (IPv6) + 8 (UDP)
			udpLen := binary.BigEndian.Uint16(pktData[44:46])
			if udpLen >= 8 {
				srcPort := binary.BigEndian.Uint16(pktData[40:42])
				dstPort := binary.BigEndian.Uint16(pktData[42:44])

				udp := getPooledUDP()
				udp.SrcPort = srcPort
				udp.DstPort = dstPort

				p.IsFastPath = true
				p.UDP = udp
				p.SrcPort = srcPort
				p.DstPort = dstPort

				payloadStart := 48
				payloadEnd := len(pktData)
				if 40+int(udpLen) <= len(pktData) {
					payloadEnd = 40 + int(udpLen)
				} else if ip6Hdr.PayloadLen > 0 && 40+int(ip6Hdr.PayloadLen) <= len(pktData) {
					payloadEnd = 40 + int(ip6Hdr.PayloadLen)
				}
				if payloadEnd > payloadStart {
					p.Payload = pktData[payloadStart:payloadEnd]
				}
				return p, nil
			}
		}
	}

	// Transparent fallback for IPv6 Extension Headers, ICMPv6, or malformed packets
	p.IsFastPath = false
	p.FallbackPacket = gopacket.NewPacket(pktData, layers.LayerTypeIPv6, gopacket.Default)
	return p, nil
}

// fastParseTCP extracts standard TCP header fields from tcpData and parses any TCP options.
func fastParseTCP(tcpData []byte, dataOffset uint8, tcpHdrLen int, tcp *layers.TCP) {
	tcp.SrcPort = layers.TCPPort(binary.BigEndian.Uint16(tcpData[0:2]))
	tcp.DstPort = layers.TCPPort(binary.BigEndian.Uint16(tcpData[2:4]))
	tcp.Seq = binary.BigEndian.Uint32(tcpData[4:8])
	tcp.Ack = binary.BigEndian.Uint32(tcpData[8:12])
	tcp.DataOffset = dataOffset
	tcp.NS = tcpData[12]&0x01 != 0
	tcp.CWR = tcpData[13]&0x80 != 0
	tcp.ECE = tcpData[13]&0x40 != 0
	tcp.URG = tcpData[13]&0x20 != 0
	tcp.ACK = tcpData[13]&0x10 != 0
	tcp.PSH = tcpData[13]&0x08 != 0
	tcp.RST = tcpData[13]&0x04 != 0
	tcp.SYN = tcpData[13]&0x02 != 0
	tcp.FIN = tcpData[13]&0x01 != 0
	tcp.Window = binary.BigEndian.Uint16(tcpData[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(tcpData[16:18])
	tcp.Urgent = binary.BigEndian.Uint16(tcpData[18:20])
	tcp.Contents = tcpData[:tcpHdrLen]

	if tcpHdrLen > 20 {
		parseTCPOptions(tcp, tcpData[20:tcpHdrLen])
	}
}

// parseTCPOptions parses TCP options into tcp.Options with 0 heap allocations.
func parseTCPOptions(tcp *layers.TCP, optBytes []byte) {
	tcp.Padding = nil

	for len(optBytes) > 0 {
		optType := layers.TCPOptionKind(optBytes[0])
		switch optType {
		case layers.TCPOptionKindEndList:
			tcp.Options = append(tcp.Options, layers.TCPOption{
				OptionType:   optType,
				OptionLength: 1,
			})
			if len(optBytes) > 1 {
				tcp.Padding = optBytes[1:]
			}
			return

		case layers.TCPOptionKindNop:
			tcp.Options = append(tcp.Options, layers.TCPOption{
				OptionType:   optType,
				OptionLength: 1,
			})
			optBytes = optBytes[1:]

		default:
			if len(optBytes) < 2 {
				return
			}
			optLen := optBytes[1]
			if optLen < 2 || int(optLen) > len(optBytes) {
				return
			}
			tcp.Options = append(tcp.Options, layers.TCPOption{
				OptionType:   optType,
				OptionLength: optLen,
				OptionData:   optBytes[2:optLen],
			})
			optBytes = optBytes[optLen:]
		}
	}
}
