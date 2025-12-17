package addr_translation

// TODO: remove main func and integrate addr translation

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type ASN struct {
	Value uint64
}

func ParseASN(s string) (ASN, error) {
	parts := strings.Split(s, ":")
	if len(parts) == 1 {
		val, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil || val > 0xffffffff {
			return ASN{}, fmt.Errorf("invalid decimal ASN: %v", err)
		}
		return ASN{Value: val}, nil
	} else if len(parts) == 3 {
		var val uint64
		for _, p := range parts {
			group, err := strconv.ParseUint(p, 16, 16)
			if err != nil {
				return ASN{}, fmt.Errorf("invalid hex group: %v", err)
			}
			val = (val << 16) | group
		}
		return ASN{Value: val}, nil
	}
	return ASN{}, fmt.Errorf("invalid ASN format")
}

type uint128 struct {
	hi uint64
	lo uint64
}

func uint128From64(v uint64) uint128 {
	return uint128{0, v}
}

func (a uint128) Lsh(n uint) uint128 {
	if n >= 128 {
		return uint128{}
	}
	if n >= 64 {
		return uint128{a.lo << (n - 64), 0}
	}
	return uint128{(a.hi << n) | (a.lo >> (64 - n)), a.lo << n}
}

func (a uint128) Rsh(n uint) uint128 {
	if n >= 128 {
		return uint128{}
	}
	if n >= 64 {
		return uint128{0, a.hi >> (n - 64)}
	}
	return uint128{
		a.hi >> n,
		(a.lo >> n) | (a.hi << (64 - n)),
	}
}

func (a uint128) Or(b uint128) uint128 {
	return uint128{a.hi | b.hi, a.lo | b.lo}
}

func bytesToUint128(b []byte) uint128 {
	return uint128{
		hi: binary.BigEndian.Uint64(b[:8]),
		lo: binary.BigEndian.Uint64(b[8:]),
	}
}

func uint128ToIP(v uint128) net.IP {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[:8], v.hi)
	binary.BigEndian.PutUint64(b[8:], v.lo)
	return net.IP(b)
}

// Encode SCION → IPv6
func ScionToIP(isd int, asn ASN, localPrefix uint64, subnet uint64, iface net.IP, subnetBits int) (net.IP, error) {
	if isd < 0 || isd >= (1<<12) {
		return nil, errors.New("ISD out of range")
	}

	var encodedASN uint64
	if asn.Value < (1 << 19) {
		encodedASN = asn.Value
	} else if asn.Value >= 0x200000000 && asn.Value <= 0x20007ffff {
		encodedASN = (1 << 19) | (asn.Value & 0x7ffff)
	} else {
		return nil, errors.New("ASN cannot be encoded")
	}

	var ipInt uint128
	ipInt = uint128From64(0xfc).Lsh(120)
	ipInt = ipInt.Or(uint128From64(uint64(isd)).Lsh(108))
	ipInt = ipInt.Or(uint128From64(encodedASN).Lsh(88))
	ipInt = ipInt.Or(uint128From64(localPrefix).Lsh(uint(64 + subnetBits)))
	ipInt = ipInt.Or(uint128From64(subnet).Lsh(64))

	if ipv4 := iface.To4(); ipv4 != nil {
		if localPrefix != 0 || subnet != 0 {
			return nil, errors.New("IPv4 requires localPrefix and subnet to be 0")
		}
		ipInt = ipInt.Or(uint128From64(0xffff).Lsh(32))
		ipInt = ipInt.Or(uint128From64(uint64(binary.BigEndian.Uint32(ipv4))))
	} else {
		if len(iface) != 16 {
			return nil, errors.New("invalid IPv6 interface address")
		}
		ipInt = ipInt.Or(bytesToUint128(iface))
	}

	return uint128ToIP(ipInt), nil
}

// Decode IPv6 → SCION components
func IPToScion(ip net.IP, subnetBits int) (isd int, asn ASN, localPrefix uint64, subnet uint64, iface net.IP, err error) {
	if len(ip) != 16 {
		err = errors.New("only IPv6 supported for SCION encoding")
		return
	}

	ip128 := bytesToUint128(ip)

	// Check prefix 0xfc
	if ip128.Rsh(120).lo != 0xfc {
		err = errors.New("not a SCION encoded IP (prefix != 0xfc)")
		return
	}

	isd = int(ip128.Rsh(108).lo & 0xFFF)

	encodedASN := ip128.Rsh(88).lo & 0x7FFFF
	if (ip128.Rsh(88).lo & (1 << 19)) != 0 {
		asn.Value = 0x200000000 | encodedASN
	} else {
		asn.Value = encodedASN
	}

	localPrefix = (ip128.Rsh(uint(64 + subnetBits)).lo) & ((1 << (24 - subnetBits)) - 1)
	subnet = (ip128.Rsh(64).lo) & ((1 << subnetBits) - 1)

	// Interface part
	if (ip128.Rsh(32).lo & 0xFFFF) == 0xFFFF {
		// IPv4-mapped
		v4 := make([]byte, 4)
		binary.BigEndian.PutUint32(v4, uint32(ip128.lo))
		iface = net.IPv4(v4[0], v4[1], v4[2], v4[3])
	} else {
		// IPv6
		b := make([]byte, 16)
		binary.BigEndian.PutUint64(b[:8], ip128.hi)
		binary.BigEndian.PutUint64(b[8:], ip128.lo)
		iface = net.IP(b)
	}

	return
}
