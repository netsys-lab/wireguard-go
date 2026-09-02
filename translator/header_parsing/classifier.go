package header_parsing

import (
	"encoding/binary"
)

// TrafficClass constants for packet classification.
// Values mirror flow.ClassPlainIP etc. Use uint8 to avoid import cycle.
const (
	ClassPlainIP       uint8 = 0
	ClassMappedSCION   uint8 = 1
	ClassNativeSCION   uint8 = 2
)

// nativeSCIONPorts is the explicit accepted SCION transport port set.
// Initially only DefaultSCIONEndhostPort (30041); structure allows growth.
var nativeSCIONPorts = []uint16{
	DefaultSCIONEndhostPort,
}

func isNativeSCIONPort(port uint16) bool {
	for _, p := range nativeSCIONPorts {
		if p == port {
			return true
		}
	}
	return false
}

// translatedIngressPorts is the no-flow fallback translate allow-list.
// Initially 8000 as per spec; MISS on this port -> stateless translate.
var translatedIngressPorts = []uint16{
	8000,
}

func isTranslatedIngressPort(port uint16) bool {
	for _, p := range translatedIngressPorts {
		if p == port {
			return true
		}
	}
	return false
}

// IsTranslatedIngressPort is exported for device/policy use.
func IsTranslatedIngressPort(port uint16) bool {
	return isTranslatedIngressPort(port)
}

// ClassifyEgress answers: what kind of Flow are we creating on TUN read
// BEFORE translation. Inner packet is still plain IP.
// - inner IPv6 dst fc00::/8 + TCP/UDP => ClassMappedSCION
// - outer IPv4/UDP/SCION or IPv6/UDP/SCION with accepted port+ver0 => ClassNativeSCION
// - else ClassPlainIP
func ClassifyEgress(packet []byte) uint8 {
	if len(packet) < 1 {
		return ClassPlainIP
	}
	// First check native SCION outer shape (IPv4 or IPv6 UDP+SCION)
	if isNativeSCIONPacket(packet) {
		return ClassNativeSCION
	}
	// Check mapped IPv6 inner (pre-translation)
	version := packet[0] >> 4
	if version == 6 && len(packet) >= 40 {
		if packet[24] == 0xfc {
			nextHeader := packet[6]
			if nextHeader == 6 || nextHeader == 17 {
				return ClassMappedSCION
			}
		}
	}
	return ClassPlainIP
}

// ClassifyIngress answers: Plain IP vs SCION transport on the outer
// packet AFTER WireGuard decryption. For known SCION flows we do NOT
// decide Native vs Mapped here; Flow.TrafficClass is the source of truth.
func ClassifyIngress(packet []byte) uint8 {
	if isNativeSCIONPacket(packet) {
		return ClassNativeSCION
	}
	// Mapped outer transport also looks like native SCION (outer UDP+SCION).
	// The distinction is not needed on ingress; we treat any SCION transport
	// as SCION needing reverse lookup. Use isSCIONTransport.
	if isSCIONTransport(packet) {
		return ClassMappedSCION
	}
	return ClassPlainIP
}

// ClassifyPacket is the legacy API kept for existing tests.
// It preserves original broad 30041-32767 and fc00 handling.
func ClassifyPacket(packet []byte) uint8 {
	if len(packet) < 40 {
		return ClassPlainIP
	}
	version := packet[0] >> 4
	if version == 4 {
		return ClassPlainIP
	}
	if version == 6 {
		if packet[24] == 0xfc {
			nextHeader := packet[6]
			if nextHeader != 17 {
				return ClassMappedSCION
			}
			udpPayloadOffset := 40 + 8
			if len(packet) < udpPayloadOffset+1 {
				return ClassMappedSCION
			}
			if packet[udpPayloadOffset]>>4 == 0 {
				return ClassMappedSCION
			}
			return ClassPlainIP
		}
		nextHeader := packet[6]
		if nextHeader != 17 {
			return ClassPlainIP
		}
		if len(packet) < 44 {
			return ClassPlainIP
		}
		dstPort := binary.BigEndian.Uint16(packet[42:44])
		if dstPort == DefaultSCIONEndhostPort || (dstPort >= 30041 && dstPort <= 32767) {
			udpPayloadOffset := 40 + 8
			if len(packet) < udpPayloadOffset+1 {
				return ClassNativeSCION
			}
			if packet[udpPayloadOffset]>>4 == 0 {
				return ClassNativeSCION
			}
		}
		return ClassPlainIP
	}
	return ClassPlainIP
}

// isNativeSCIONPacket detects outer IPv4/UDP/SCION or IPv6/UDP/SCION
// with accepted port and SCION common header version 0.
func isNativeSCIONPacket(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	version := packet[0] >> 4
	if version == 4 {
		return isNativeSCIONOverIPv4(packet)
	}
	if version == 6 {
		return isNativeSCIONOverIPv6(packet)
	}
	return false
}

func isNativeSCIONOverIPv4(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || ihl > len(packet) {
		return false
	}
	if packet[9] != 17 { // UDP
		return false
	}
	if len(packet) < ihl+8 {
		return false
	}
	dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
	if !isNativeSCIONPort(dstPort) {
		return false
	}
	payloadOff := ihl + 8
	if len(packet) < payloadOff+1 {
		return false
	}
	return packet[payloadOff]>>4 == 0
}

func isNativeSCIONOverIPv6(packet []byte) bool {
	if len(packet) < 40 {
		return false
	}
	if packet[6] != 17 {
		return false
	}
	if len(packet) < 44 {
		return false
	}
	dstPort := binary.BigEndian.Uint16(packet[42:44])
	if !isNativeSCIONPort(dstPort) {
		return false
	}
	payloadOff := 40 + 8
	if len(packet) < payloadOff+1 {
		return false
	}
	return packet[payloadOff]>>4 == 0
}

func isSCIONTransport(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	version := packet[0] >> 4
	var payloadOff int
	var udpDstPort uint16
	if version == 4 {
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || ihl > len(packet) || packet[9] != 17 {
			return false
		}
		if len(packet) < ihl+8 {
			return false
		}
		udpDstPort = binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
		payloadOff = ihl + 8
	} else if version == 6 {
		if len(packet) < 40 || packet[6] != 17 {
			return false
		}
		if len(packet) < 44 {
			return false
		}
		udpDstPort = binary.BigEndian.Uint16(packet[42:44])
		payloadOff = 40 + 8
	} else {
		return false
	}
	_ = udpDstPort
	if len(packet) < payloadOff+1 {
		return false
	}
	return packet[payloadOff]>>4 == 0
}
