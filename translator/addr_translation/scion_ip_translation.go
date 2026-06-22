package addr_translation

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"strconv"
	"strings"
)

const (
	SCIONPrefixFirstByte = 0xfc

	asnBits      = 48
	maxASN       = (uint64(1) << asnBits) - 1
	maxBGPASN    = (uint64(1) << 32) - 1
	groupBits    = 16
	groupMax     = (uint64(1) << groupBits) - 1
	encodedASLen = 20
)

type ASN struct {
	Value uint64
}

func ParseASN(s string) (ASN, error) {
	parts := strings.Split(s, ":")

	switch len(parts) {
	case 1:
		val, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil || val > maxBGPASN {
			return ASN{}, fmt.Errorf("invalid decimal ASN: %q", s)
		}
		return ASN{Value: val}, nil

	case 3:
		var val uint64
		for _, p := range parts {
			group, err := strconv.ParseUint(p, 16, 16)
			if err != nil || group > groupMax {
				return ASN{}, fmt.Errorf("invalid hexadecimal ASN group: %q", p)
			}
			val = (val << groupBits) | group
		}
		return ASN{Value: val}, nil

	default:
		return ASN{}, fmt.Errorf("invalid ASN format: %q", s)
	}
}

func (a ASN) String() string {
	if a.Value <= maxBGPASN {
		return strconv.FormatUint(a.Value, 10)
	}

	return fmt.Sprintf("%x:%x:%x",
		(a.Value>>(2*groupBits))&groupMax,
		(a.Value>>groupBits)&groupMax,
		a.Value&groupMax,
	)
}

func encodeASN(asn ASN) (uint64, error) {
	if asn.Value > maxASN {
		return 0, fmt.Errorf("ASN out of range: %d", asn.Value)
	}

	if asn.Value < (uint64(1) << 19) {
		return asn.Value, nil
	}

	if 0x2_0000_0000 <= asn.Value && asn.Value <= 0x2_0007_ffff {
		return (uint64(1) << 19) | (asn.Value & 0x7ffff), nil
	}

	return 0, fmt.Errorf("ASN cannot be encoded: %s", asn.String())
}

func decodeASN(encoded uint64) ASN {
	if encoded&(uint64(1)<<19) != 0 {
		return ASN{Value: 0x2_0000_0000 | (encoded & 0x7ffff)}
	}
	return ASN{Value: encoded}
}

func validateSubnetBits(subnetBits uint) error {
	if subnetBits > 24 {
		return fmt.Errorf("subnetBits must be in [0, 24], got %d", subnetBits)
	}
	return nil
}

func checkLocalPrefixSubnet(localPrefix, subnet uint64, subnetBits uint) error {
	if err := validateSubnetBits(subnetBits); err != nil {
		return err
	}

	localPrefixBits := 24 - subnetBits

	if localPrefixBits == 0 {
		if localPrefix != 0 {
			return fmt.Errorf("invalid local prefix %x for subnetBits=%d", localPrefix, subnetBits)
		}
	} else if localPrefix >= (uint64(1) << localPrefixBits) {
		return fmt.Errorf("invalid local prefix %x for subnetBits=%d", localPrefix, subnetBits)
	}

	if subnetBits == 0 {
		if subnet != 0 {
			return fmt.Errorf("invalid subnet %x for subnetBits=%d", subnet, subnetBits)
		}
	} else if subnet >= (uint64(1) << subnetBits) {
		return fmt.Errorf("invalid subnet %x for subnetBits=%d", subnet, subnetBits)
	}

	return nil
}

func parseHex(raw string, length uint) (uint64, error) {
	parsePart := func(s string) (uint64, int, error) {
		if s == "" {
			return 0, 0, nil
		}

		var n uint64
		groups := strings.Split(s, ":")
		for _, g := range groups {
			if g == "" {
				return 0, 0, fmt.Errorf("invalid empty hex group")
			}

			v, err := strconv.ParseUint(g, 16, 16)
			if err != nil {
				return 0, 0, fmt.Errorf("invalid hex group %q", g)
			}

			n = (n << 16) | v
		}
		return n, len(groups), nil
	}

	parts := strings.Split(raw, "::")
	if len(parts) > 2 {
		return 0, fmt.Errorf(":: may appear only once")
	}

	lengthGroups := int((length + 15) / 16)

	nLo, _, err := parsePart(parts[len(parts)-1])
	if err != nil {
		return 0, err
	}

	var nHi uint64
	var groupsHi int
	if len(parts) > 1 {
		nHi, groupsHi, err = parsePart(parts[0])
		if err != nil {
			return 0, err
		}
	}

	if lengthGroups-groupsHi < 0 {
		return 0, fmt.Errorf("invalid number of groups")
	}

	nHi <<= 16 * uint(lengthGroups-groupsHi)
	n := nHi | nLo

	if length == 0 {
		if n != 0 {
			return 0, fmt.Errorf("number too large")
		}
		return 0, nil
	}

	if bits.Len64(n) > int(length) {
		return 0, fmt.Errorf("number too large")
	}

	return n, nil
}

func formatHex(n uint64) string {
	if n == 0 {
		return "0"
	}

	groupCount := (bits.Len64(n) + 15) / 16
	out := make([]string, 0, groupCount)

	for i := groupCount; i > 0; i-- {
		shift := uint(16 * (i - 1))
		out = append(out, fmt.Sprintf("%x", (n>>shift)&0xffff))
	}

	return strings.Join(out, ":")
}

func parseInterface(raw string, localPrefix, subnet uint64) (uint64, bool, error) {
	if ip := net.ParseIP(raw); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			if localPrefix != 0 || subnet != 0 {
				return 0, false, errors.New("local prefix and subnet must be zero in SCION-IPv4-mapped addresses")
			}
			return (uint64(0x0000ffff) << 32) | uint64(binary.BigEndian.Uint32(ip4)), true, nil
		}
	}

	iface, err := parseHex(raw, 64)
	if err != nil {
		return 0, false, fmt.Errorf("invalid interface: %w", err)
	}

	return iface, false, nil
}

// S2IP is the direct Go equivalent of the Python s2ip() function.
// Input format: ISD-ASN Local-Prefix Subnet Interface.
func S2IP(isdASN, localPrefixRaw, subnetRaw, interfaceRaw string, subnetBits uint) (net.IP, error) {
	if err := validateSubnetBits(subnetBits); err != nil {
		return nil, err
	}

	parts := strings.Split(isdASN, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid isd-asn: %q", isdASN)
	}

	isd64, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil || isd64 >= (uint64(1)<<12) {
		return nil, fmt.Errorf("ISD cannot be encoded: %q", parts[0])
	}

	asn, err := ParseASN(parts[1])
	if err != nil {
		return nil, err
	}

	localPrefix, err := parseHex(localPrefixRaw, 24-subnetBits)
	if err != nil {
		return nil, fmt.Errorf("invalid local prefix: %w", err)
	}

	subnet, err := parseHex(subnetRaw, subnetBits)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %w", err)
	}

	iface64, _, err := parseInterface(interfaceRaw, localPrefix, subnet)
	if err != nil {
		return nil, err
	}

	return MapToIPv6(uint16(isd64), asn, uint32(localPrefix), uint32(subnet), iface64, subnetBits)
}

// MapToIPv6 maps the already parsed SCION parts to the IPv6 address.
// Layout:
// fc | ISD(12) | encoded-AS(20) | local-prefix/subnet(24) | interface(64)
func MapToIPv6(isd uint16, asn ASN, localPrefix, subnet uint32, iface64 uint64, subnetBits uint) (net.IP, error) {
	if isd >= (1 << 12) {
		return nil, fmt.Errorf("ISD cannot be encoded: %d", isd)
	}

	if err := checkLocalPrefixSubnet(uint64(localPrefix), uint64(subnet), subnetBits); err != nil {
		return nil, err
	}

	encodedASN, err := encodeASN(asn)
	if err != nil {
		return nil, err
	}

	hi := (uint64(SCIONPrefixFirstByte) << 56) |
		(uint64(isd) << 44) |
		(encodedASN << 24) |
		(uint64(localPrefix) << subnetBits) |
		uint64(subnet)

	ip := make(net.IP, net.IPv6len)
	binary.BigEndian.PutUint64(ip[0:8], hi)
	binary.BigEndian.PutUint64(ip[8:16], iface64)

	return ip, nil
}

// ScionToIP keeps your old Go API, but now implements the Python layout correctly.
// For IPv6-like iface values, only ::/64-style interface IDs are accepted,
// e.g. ::1, ::ff00:1. Full IPv6 addresses like 2001:db8::1 are rejected.
func ScionToIP(isd int, asn ASN, localPrefix, subnet uint64, iface net.IP, subnetBits int) (net.IP, error) {
	if isd < 0 || isd >= (1<<12) {
		return nil, errors.New("ISD out of range")
	}

	if subnetBits < 0 {
		return nil, errors.New("subnetBits must be in [0, 24]")
	}

	sb := uint(subnetBits)
	if err := checkLocalPrefixSubnet(localPrefix, subnet, sb); err != nil {
		return nil, err
	}

	var iface64 uint64

	if ip4 := iface.To4(); ip4 != nil {
		if localPrefix != 0 || subnet != 0 {
			return nil, errors.New("IPv4 requires localPrefix and subnet to be 0")
		}
		iface64 = (uint64(0x0000ffff) << 32) | uint64(binary.BigEndian.Uint32(ip4))
	} else {
		ip16 := iface.To16()
		if ip16 == nil {
			return nil, errors.New("invalid interface address")
		}

		hi := binary.BigEndian.Uint64(ip16[0:8])
		if hi != 0 {
			return nil, fmt.Errorf("IPv6 interface must fit in low 64 bits, got %s", iface.String())
		}

		iface64 = binary.BigEndian.Uint64(ip16[8:16])
	}

	return MapToIPv6(uint16(isd), asn, uint32(localPrefix), uint32(subnet), iface64, sb)
}

func IsSCIONMapped(ip net.IP) bool {
	ip = ip.To16()
	return ip != nil && ip[0] == SCIONPrefixFirstByte
}

// UnmapIPv6 keeps the signature your translator currently wants.
// Important: for non-IPv4 interfaces this returns ::interface64,
// not the original fc00::/8 mapped IPv6 address.
func UnmapIPv6(ip net.IP, subnetBits uint) (
	uint16,
	uint64,
	uint32,
	uint32,
	net.IP,
	bool,
	error,
) {
	if err := validateSubnetBits(subnetBits); err != nil {
		return 0, 0, 0, 0, nil, false, err
	}

	ip = ip.To16()
	if ip == nil || ip[0] != SCIONPrefixFirstByte {
		return 0, 0, 0, 0, nil, false, errors.New("not a SCION-mapped IPv6 address")
	}

	hi := binary.BigEndian.Uint64(ip[0:8])
	lo := binary.BigEndian.Uint64(ip[8:16])

	isd := uint16((hi >> 44) & 0x0fff)
	encodedASN := (hi >> 24) & 0x000fffff
	asn := decodeASN(encodedASN)

	subnetMask := uint64(0)
	if subnetBits > 0 {
		subnetMask = (uint64(1) << subnetBits) - 1
	}
	subnet := uint32(hi & subnetMask)

	localPrefixBits := 24 - subnetBits
	localPrefixMask := uint64(0)
	if localPrefixBits > 0 {
		localPrefixMask = (uint64(1) << localPrefixBits) - 1
	}
	localPrefix := uint32((hi >> subnetBits) & localPrefixMask)

	var host net.IP
	hostIsIPv4 := false

	if (lo & 0xffffffff00000000) == 0x0000ffff00000000 {
		v4 := make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(v4, uint32(lo))
		host = net.IPv4(v4[0], v4[1], v4[2], v4[3])
		hostIsIPv4 = true
	} else {
		host = make(net.IP, net.IPv6len)
		binary.BigEndian.PutUint64(host[8:16], lo)
	}

	return isd, asn.Value, localPrefix, subnet, host, hostIsIPv4, nil
}

// IPToScion keeps your old unit-test API.
func IPToScion(ip net.IP, subnetBits int) (
	isd int,
	asn ASN,
	localPrefix uint64,
	subnet uint64,
	iface net.IP,
	err error,
) {
	if subnetBits < 0 {
		err = errors.New("subnetBits must be in [0, 24]")
		return
	}

	gotISD, gotASN, gotLocalPrefix, gotSubnet, gotIface, _, err := UnmapIPv6(ip, uint(subnetBits))
	if err != nil {
		return
	}

	return int(gotISD), ASN{Value: gotASN}, uint64(gotLocalPrefix), uint64(gotSubnet), gotIface, nil
}

// IP2S is the direct Go equivalent of the Python ip2s() function.
func IP2S(ip net.IP, subnetBits uint) (string, error) {
	isd, asnVal, localPrefix, subnet, iface, hostIsIPv4, err := UnmapIPv6(ip, subnetBits)
	if err != nil {
		return "", err
	}

	var ifaceStr string
	if hostIsIPv4 {
		ifaceStr = iface.To4().String()
	} else {
		ip16 := iface.To16()
		if ip16 == nil {
			return "", errors.New("invalid decoded interface")
		}
		ifaceStr = formatHex(binary.BigEndian.Uint64(ip16[8:16]))
	}

	return fmt.Sprintf("%d-%s %s %s %s",
		isd,
		ASN{Value: asnVal}.String(),
		formatHex(uint64(localPrefix)),
		formatHex(uint64(subnet)),
		ifaceStr,
	), nil
}
