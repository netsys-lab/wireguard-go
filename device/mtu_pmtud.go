package device

import (
	"encoding/binary"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// SCIONEffectiveMTU is the safe payload MTU for SCION (1280 is IPv6 minimum, leaving room for SCION headers).
const SCIONEffectiveMTU = 1280

// checkAndGeneratePTB checks if the packet exceeds the MTU or is fragmented.
// If it is, it generates a synthetic ICMP/ICMPv6 Packet Too Big message and returns it.
// It returns nil if the packet is fine.
func checkAndGeneratePTB(pkt []byte) []byte {
	if len(pkt) == 0 {
		return nil
	}
	version := pkt[0] >> 4
	if version == 4 {
		if len(pkt) < ipv4.HeaderLen {
			return nil
		}
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < ihl {
			return nil
		}
		fragOffset := binary.BigEndian.Uint16(pkt[6:8])
		df := (fragOffset & 0x4000) != 0
		mf := (fragOffset & 0x2000) != 0
		offset := fragOffset & 0x1FFF

		needsPTB := false
		if len(pkt) > SCIONEffectiveMTU && df {
			needsPTB = true
		} else if mf || offset > 0 {
			needsPTB = true
		}

		if !needsPTB {
			return nil
		}

		if pkt[9] == 1 /* IPPROTO_ICMP */ {
			return nil
		}

		payloadLen := ihl + 8
		if len(pkt) < payloadLen {
			payloadLen = len(pkt)
		}

		outLen := 20 + 8 + payloadLen
		out := make([]byte, outLen)

		out[0] = 0x45
		out[1] = 0x00
		binary.BigEndian.PutUint16(out[2:4], uint16(outLen))
		binary.BigEndian.PutUint16(out[4:6], 0)
		binary.BigEndian.PutUint16(out[6:8], 0)
		out[8] = 64
		out[9] = 1

		copy(out[12:16], pkt[16:20])
		copy(out[16:20], pkt[12:16])

		binary.BigEndian.PutUint16(out[10:12], calcChecksum(out[0:20]))

		out[20] = 3
		out[21] = 4
		binary.BigEndian.PutUint16(out[24:26], 0)
		binary.BigEndian.PutUint16(out[26:28], SCIONEffectiveMTU)

		copy(out[28:], pkt[:payloadLen])

		binary.BigEndian.PutUint16(out[22:24], calcChecksum(out[20:]))

		return out

	} else if version == 6 {
		if len(pkt) < ipv6.HeaderLen {
			return nil
		}

		needsPTB := false
		if len(pkt) > SCIONEffectiveMTU {
			needsPTB = true
		} else {
			nextHeader := pkt[6]
			if nextHeader == 44 /* Fragment Header */ {
				needsPTB = true
			}
		}

		if !needsPTB {
			return nil
		}

		nextHeader := pkt[6]
		if nextHeader == 58 /* IPPROTO_ICMPV6 */ {
			return nil
		}

		payloadLen := len(pkt)
		if 40+8+payloadLen > 1280 {
			payloadLen = 1280 - 40 - 8
		}

		outLen := 40 + 8 + payloadLen
		out := make([]byte, outLen)

		binary.BigEndian.PutUint32(out[0:4], 0x60000000)
		binary.BigEndian.PutUint16(out[4:6], uint16(8+payloadLen))
		out[6] = 58
		out[7] = 64

		copy(out[8:24], pkt[24:40])
		copy(out[24:40], pkt[8:24])

		out[40] = 2
		out[41] = 0
		binary.BigEndian.PutUint32(out[44:48], SCIONEffectiveMTU)

		copy(out[48:], pkt[:payloadLen])

		pseudoLen := 16 + 16 + 4 + 4
		pseudo := make([]byte, pseudoLen+8+payloadLen)
		copy(pseudo[0:16], out[8:24])
		copy(pseudo[16:32], out[24:40])
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(8+payloadLen))
		pseudo[39] = 58
		copy(pseudo[40:], out[40:])

		binary.BigEndian.PutUint16(out[42:44], calcChecksum(pseudo))

		return out
	}

	return nil
}

func calcChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
