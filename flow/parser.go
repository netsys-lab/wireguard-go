package flow

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	ProtocolTCP    = 6
	ProtocolUDP    = 17
	ProtocolICMPv6 = 58
	ProtocolSCMP   = 1 // SCION SCMP informational, used for native SCION flows
)

var (
	ErrInvalidIPv4      = errors.New("invalid IPv4 packet")
	ErrInvalidIPv6      = errors.New("invalid IPv6 packet")
	ErrTruncated        = errors.New("truncated packet")
	ErrIPv4Fragment     = errors.New("non-initial IPv4 fragment")
	ErrIPv6ExtensionHdr = errors.New("IPv6 extension header not supported")
	ErrUnsupportedProto = errors.New("unsupported transport protocol")
)

type PacketMetadata struct {
	IPVersion    uint8
	Protocol     uint8
	Source       Endpoint
	Destination  Endpoint
	SrcIA        string     // local SCION AS; empty for IP; set by caller
	DstIA        string     // remote SCION dst AS; empty for IP; set by caller
	SCIONDstIP   netip.Addr // authoritative SCION dst IPv4; zero for IP; set by caller
	TrafficClass TrafficClass
}

func ParsePacketMetadata(packet []byte) (PacketMetadata, error) {
	if len(packet) < 1 {
		return PacketMetadata{}, ErrTruncated
	}

	version := packet[0] >> 4
	switch version {
	case 4:
		return parseIPv4(packet)
	case 6:
		return parseIPv6(packet)
	default:
		return PacketMetadata{}, ErrInvalidIPv4
	}
}

func parseIPv4(packet []byte) (PacketMetadata, error) {
	if len(packet) < 20 {
		return PacketMetadata{}, ErrTruncated
	}

	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || ihl > len(packet) {
		return PacketMetadata{}, ErrInvalidIPv4
	}

	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl || totalLen > len(packet) {
		return PacketMetadata{}, ErrTruncated
	}

	flagsAndOffset := binary.BigEndian.Uint16(packet[6:8])
	fragmentOffset := flagsAndOffset & 0x1FFF
	if fragmentOffset > 0 {
		return PacketMetadata{}, ErrIPv4Fragment
	}

	protocol := packet[9]

	if protocol != ProtocolTCP && protocol != ProtocolUDP {
		return PacketMetadata{}, ErrUnsupportedProto
	}

	if ihl+4 > len(packet) {
		return PacketMetadata{}, ErrTruncated
	}

	srcIP := netip.AddrFrom4([4]byte(packet[12:16]))
	dstIP := netip.AddrFrom4([4]byte(packet[16:20]))
	srcPort := binary.BigEndian.Uint16(packet[ihl : ihl+2])
	dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])

	return PacketMetadata{
		IPVersion:   4,
		Protocol:    protocol,
		Source:      Endpoint{Addr: srcIP, Port: srcPort},
		Destination: Endpoint{Addr: dstIP, Port: dstPort},
	}, nil
}

func parseIPv6(packet []byte) (PacketMetadata, error) {
	if len(packet) < 40 {
		return PacketMetadata{}, ErrTruncated
	}

	if packet[0]>>4 != 6 {
		return PacketMetadata{}, ErrInvalidIPv6
	}

	payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	totalLen := 40 + payloadLen
	if totalLen > len(packet) {
		return PacketMetadata{}, ErrTruncated
	}

	nextHeader := packet[6]

	if nextHeader == ProtocolTCP || nextHeader == ProtocolUDP {
		if 40+4 > len(packet) {
			return PacketMetadata{}, ErrTruncated
		}
		srcIP := netip.AddrFrom16([16]byte(packet[8:24]))
		dstIP := netip.AddrFrom16([16]byte(packet[24:40]))
		srcPort := binary.BigEndian.Uint16(packet[40:42])
		dstPort := binary.BigEndian.Uint16(packet[42:44])
		return PacketMetadata{
			IPVersion:   6,
			Protocol:    nextHeader,
			Source:      Endpoint{Addr: srcIP, Port: srcPort},
			Destination: Endpoint{Addr: dstIP, Port: dstPort},
		}, nil
	}

	if nextHeader == ProtocolICMPv6 {
		if 40+8 > len(packet) {
			return PacketMetadata{}, ErrTruncated
		}
		srcIP := netip.AddrFrom16([16]byte(packet[8:24]))
		dstIP := netip.AddrFrom16([16]byte(packet[24:40]))
		icmpType := packet[40]
		// For Echo Request/Reply, use Identifier as port for both endpoints to keep request/reply same Flow
		var identifier uint16
		if icmpType == 128 || icmpType == 129 { // Echo Request/Reply
			if 40+6 <= len(packet) {
				identifier = binary.BigEndian.Uint16(packet[44:46])
			}
		}
		// Use identifier for both src and dst port to ensure canonical key stability
		return PacketMetadata{
			IPVersion:   6,
			Protocol:    ProtocolICMPv6,
			Source:      Endpoint{Addr: srcIP, Port: identifier},
			Destination: Endpoint{Addr: dstIP, Port: identifier},
		}, nil
	}

	return PacketMetadata{}, ErrIPv6ExtensionHdr
}
