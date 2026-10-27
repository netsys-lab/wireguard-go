package header_parsing

// TrafficClass constants for packet classification.
// Values mirror flow.ClassPlainIP etc. Use uint8 to avoid import cycle.
const (
	ClassPlainIP     uint8 = 0
	ClassMappedSCION uint8 = 1
	ClassNativeSCION uint8 = 2
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
// - outer IPv4/UDP/SCION or IPv6/UDP/SCION with valid SCION header => ClassNativeSCION
// - inner IPv6 dst fc00::/8 + TCP/UDP/ICMPv6 => ClassMappedSCION
// - else ClassPlainIP
func ClassifyEgress(packet []byte) uint8 {
	if len(packet) < 1 {
		return ClassPlainIP
	}
	// First check native SCION outer shape (IPv4 or IPv6 UDP+SCION)
	if isValidOuterSCION(packet) {
		return ClassNativeSCION
	}
	// Check mapped IPv6 inner (pre-translation)
	version := packet[0] >> 4
	if version == 6 && len(packet) >= 40 {
		if packet[24] == 0xfc {
			nextHeader := packet[6]
			if nextHeader == 6 || nextHeader == 17 || nextHeader == 58 {
				return ClassMappedSCION
			}
		}
	}
	return ClassPlainIP
}

// ClassifyIngress answers: Plain IP vs SCION transport on the outer
// packet AFTER WireGuard decryption. Both Native and Mapped SCION arrive
// over outer IP/UDP with a valid SCION header.
// For known SCION flows we do NOT decide Native vs Mapped here;
// Flow.TrafficClass in the FlowManager is the source of truth.
func ClassifyIngress(packet []byte) uint8 {
	if isValidOuterSCION(packet) {
		return ClassNativeSCION
	}
	return ClassPlainIP
}

// isValidOuterSCION prüft autoritativ, ob es sich um ein valides äußeres SCION-Paket
// über IPv4/UDP oder IPv6/UDP handelt (Port-unabhängig für Endhost-Port 30041 und
// alle Border-Router Underlay-Ports 31002, 31004 etc.).
//
// Ein valides äußeres SCION-Paket erfüllt folgende Kriterien:
// 1. IP-Version ist 4 oder 6 mit gültiger Header-Länge.
// 2. Transport-Protokoll ist UDP (Protocol/NextHeader == 17).
// 3. Das erste Byte der UDP-Payload besitzt die SCION-Version 0 (Bits 0-3 = 0).
func isValidOuterSCION(packet []byte) bool {
	// Schritt 1: Mindestlänge für den kleinstmöglichen IP-Header (IPv4 = 20 Bytes)
	if len(packet) < 20 {
		return false
	}

	// Schritt 2: IP-Version aus den oberen 4 Bits (High-Nibble) von Byte 0 extrahieren
	version := packet[0] >> 4
	switch version {
	case 4:
		// --- Fall A: IPv4 ---
		// Das untere Nibble von Byte 0 (IHL: Internet Header Length) gibt die Länge
		// des IPv4-Headers in 32-Bit-Wörtern (4 Bytes) an. Normalerweise 5 (5 * 4 = 20 Bytes).
		ihl := int(packet[0]&0x0f) * 4
		// Plausibilitätsprüfung: Header muss mindestens 20 Bytes groß sein und darf
		// nicht größer als das eigentliche Paket sein (verhindert Buffer-Overflow/Panics).
		if ihl < 20 || ihl > len(packet) {
			return false
		}

		// Byte 9 ist das "Protocol"-Feld im IPv4-Header.
		// SCION wird immer in UDP gekapselt (UDP Protocol Number = 17).
		if packet[9] != 17 {
			return false
		}

		// Ein UDP-Header ist immer exakt 8 Bytes lang.
		// Prüfen, ob das Paket mindestens den kompletten IPv4-Header + 8 Bytes UDP-Header enthält.
		if len(packet) < ihl+8 {
			return false
		}

		// Offset zur UDP-Payload (wo der SCION-Header beginnt)
		payloadOff := ihl + 8
		// Mindestens 1 Byte SCION-Header-Payload muss vorhanden sein, um das Versions-Nibble zu prüfen
		if len(packet) < payloadOff+1 {
			return false
		}

		// SCION Common Header Version-Check:
		// Die ersten 4 Bits (High-Nibble) des SCION-Headers definieren die SCION-Version.
		// Laut SCION-Spezifikation MUSS die SCION-Version 0 sein (0b0000).
		return packet[payloadOff]>>4 == 0

	case 6:
		// --- Fall B: IPv6 ---
		// Ein fester IPv6-Header ist immer exakt 40 Bytes lang.
		if len(packet) < 40 {
			return false
		}

		// Byte 6 ist das "Next Header"-Feld im IPv6-Header.
		// SCION wird in UDP gekapselt (UDP Protocol Number = 17).
		if packet[6] != 17 {
			return false
		}

		// Offset zur UDP-Payload: Fester IPv6-Header (40 Bytes) + UDP-Header (8 Bytes) = 48 Bytes.
		payloadOff := 40 + 8
		// Mindestens 1 Byte SCION-Header-Payload muss vorhanden sein
		if len(packet) < payloadOff+1 {
			return false
		}

		// SCION Common Header Version-Check:
		// Oberes Nibble des ersten SCION-Payload-Bytes muss Version 0 sein.
		return packet[payloadOff]>>4 == 0

	default:
		// Weder IPv4 noch IPv6
		return false
	}
}
