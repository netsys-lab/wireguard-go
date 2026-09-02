package header_parsing

import (
	"encoding/binary"
)

// TrafficClass constants for packet classification
const (
	ClassPlainIP       uint8 = 0
	ClassMappedSCION   uint8 = 1
	ClassNativeSCION   uint8 = 2
)

// ClassifyPacket performs zero-allocation, lightweight classification of inbound packets.
//
// Returns:
//   - ClassPlainIP: Plain IP packet, no translation needed
//   - ClassMappedSCION: SCION-mapped IPv6, requires TranslateIngress
//   - ClassNativeSCION: Native SCION over UDP, fast-path to dispatcher
//
// This function only inspects the outer headers without full gopacket parsing.
func ClassifyPacket(packet []byte) uint8 {
	if len(packet) < 40 {
		// Minimum IPv6 header length; anything smaller is plain IP or malformed
		return ClassPlainIP
	}

	// Check IP version (first nibble of first byte)
	version := packet[0] >> 4

	// IPv4: always plain IP (no SCION mapping over IPv4)
	if version == 4 {
		return ClassPlainIP
	}

	// IPv6: check destination prefix and payload
	if version == 6 {
		// Destination address is at bytes 24:40 of IPv6 header
		// Check if destination matches SCION-mapped prefix fc00::/8
		if packet[24] == 0xfc {
			// SCION-mapped IPv6 (fc00::/8)
			// Still verify it's UDP with SCION payload to avoid false positives
			nextHeader := packet[6]
			if nextHeader != 17 { // 17 = UDP
				return ClassMappedSCION // Could be SCMP or other SCION transport
			}

			// Peek at UDP payload to check for SCION version
			// UDP header is 8 bytes; standard IPv6 header is 40 bytes
			udpPayloadOffset := 40 + 8
			if len(packet) < udpPayloadOffset+1 {
				return ClassMappedSCION // Assume it's SCION; error will be caught in TranslateIngress
			}

			// Check SCION version (first nibble of SCION common header = 0)
			scionVersion := packet[udpPayloadOffset] >> 4
			if scionVersion == 0 {
				return ClassMappedSCION
			}

			// Not valid SCION; likely plain UDP
			return ClassPlainIP
		}

		// Non-SCION-mapped IPv6: check if it's native SCION (UDP with SCION payload)
		nextHeader := packet[6]
		if nextHeader != 17 { // 17 = UDP
			// Not UDP; plain IPv6 traffic
			return ClassPlainIP
		}

		// Is UDP; check destination port and SCION header
		if len(packet) < 44 { // 40 (IPv6) + 4 (UDP header min) + 0 (payload min)
			return ClassPlainIP
		}

		// UDP destination port at bytes 42:44
		dstPort := binary.BigEndian.Uint16(packet[42:44])

		// Check if port matches native SCION dispatcher port (30041) or typical SCION range
		// SCION endhost/dispatcher port is 30041
		// Also check for typical dispatch range (e.g., 30041-30051)
		if dstPort == DefaultSCIONEndhostPort || (dstPort >= 30041 && dstPort <= 32767) {
			// Likely native SCION; check SCION version in payload
			udpPayloadOffset := 40 + 8
			if len(packet) < udpPayloadOffset+1 {
				return ClassNativeSCION // Assume SCION by port; error will be caught elsewhere
			}

			scionVersion := packet[udpPayloadOffset] >> 4
			if scionVersion == 0 {
				return ClassNativeSCION
			}
		}

		// Non-SCION IPv6 with UDP
		return ClassPlainIP
	}

	// Unknown IP version
	return ClassPlainIP
}
