package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	// SCION-mapped IPv6 prefix = fc00::/8
	SCIONPrefixFirstByte = 0xfc
)

// use only when sure that IPv4 is stored in the low 32 bits of the interface ID
func forceUnmapIPv6(ip net.IP) (
	uint16,
	uint64,
	net.IP,
	error,
) {
	ip = ip.To16()
	if ip == nil || ip[0] != SCIONPrefixFirstByte {
		return 0, 0, nil, errors.New("not a scion-mapped ipv6")
	}
	hi := binary.BigEndian.Uint64(ip[0:8])
	lo := binary.BigEndian.Uint64(ip[8:16])

	encodedASN := uint64((hi >> 24) & 0x000fffff)

	var asn uint64
	if encodedASN&(1<<19) != 0 {
		// colon-style AS encoded as 0x200000000 | low 19 bits
		asn = 0x200000000 | (encodedASN & 0x7ffff)
	} else {
		// decimal/BGP-style AS
		asn = encodedASN
	}

	isd := uint16((hi >> 44) & 0x0fff)

	var hostIP net.IP

	// IPv4 address stored in low 32 bits
	interface64 := lo // low 64 bits are interface identifier
	ipv4 := make(net.IP, 4)
	binary.BigEndian.PutUint32(ipv4, uint32(interface64&0xffffffff))
	hostIP = net.IPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3])

	return isd, asn, hostIP, nil
}

func UnmapIPv6(ip net.IP, subnetBits uint) (
	uint16,
	uint64,
	uint32,
	uint32,
	net.IP,
	bool,
	error,
) {
	ip = ip.To16()
	if ip == nil || ip[0] != SCIONPrefixFirstByte {
		return 0, 0, 0, 0, nil, false, errors.New("not a scion-mapped ipv6")
	}

	hi := binary.BigEndian.Uint64(ip[0:8])
	lo := binary.BigEndian.Uint64(ip[8:16])

	interface64 := lo // low 64 bits are interface identifier

	// subnet = low 'subnetBits' of hi
	if subnetBits > 24 {
		return 0, 0, 0, 0, nil, false, errors.New("subnetBits must be <= 24")
	}
	subnetMask := uint64((1 << subnetBits) - 1)
	subnet := uint32(hi & subnetMask)

	localPrefixMask := uint64((1 << (24 - subnetBits)) - 1)
	localPrefix := uint32((hi >> subnetBits) & localPrefixMask)

	//asn := uint32((hi >> 24) & 0x000fffff)
	encodedASN := uint64((hi >> 24) & 0x000fffff)

	var asn uint64
	if encodedASN&(1<<19) != 0 {
		// colon-style AS encoded as 0x200000000 | low 19 bits
		asn = 0x200000000 | (encodedASN & 0x7ffff)
	} else {
		// decimal/BGP-style AS
		asn = encodedASN
	}

	isd := uint16((hi >> 44) & 0x0fff)

	// check for IPv4-mapped host inside the 64-bit interface ID
	high32 := uint32(interface64 >> 32)
	var hostIP net.IP
	hostIsIPv4 := false
	if high32 == 0x0000ffff && localPrefix == 0 && subnet == 0 {
		// IPv4 address stored in low 32 bits
		ipv4 := make(net.IP, 4)
		binary.BigEndian.PutUint32(ipv4, uint32(interface64&0xffffffff))
		hostIP = net.IPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3])
		hostIsIPv4 = true
	} else {
		// not IPv4-mapped host: the host ID is a 64-bit interface ID
		hostIP = make(net.IP, net.IPv6len)
		copy(hostIP, ip.To16())
		hostIsIPv4 = false
	}

	return isd, asn, localPrefix, subnet, hostIP, hostIsIPv4, nil
}

func formatSCIONAS(asn uint64) string {
	// Colon-style SCION AS: 48-bit value printed as x:y:z
	if asn > 0xffffffff {
		return fmt.Sprintf("%x:%x:%x",
			uint16(asn>>32),
			uint16(asn>>16),
			uint16(asn),
		)
	}

	//Else Case: <= 0xffffffff -> decimal/BGP-style AS

	// BGP-style / decimal AS
	return fmt.Sprintf("%d", asn)
}

func formatIA(isd uint16, asn uint64) string {
	return fmt.Sprintf("%d-%s", isd, formatSCIONAS(asn))
}

func main() {
	/*
		if len(os.Args) != 1 {
			fmt.Fprintf(os.Stderr, "usage: go run ./unmap_ipv6 <IPV6>\n")
			fmt.Fprintf(os.Stderr, "example: go run ./unmap_ipv6 fc04:800:900::ffff:8184:af68\n")
			os.Exit(1)
		}
	*/
	ip := net.ParseIP("fc04:800:900::ffff:8184:af68")
	isd, asn, hostIP, err := forceUnmapIPv6(ip)
	if err != nil {
		panic(err)
	}

	fmt.Println(isd, formatSCIONAS(asn), hostIP)

	isd, asn, localPrefix, subnet, hostIP, hostIsIPv4, err := UnmapIPv6(ip, 8)

	fmt.Printf("%d %s %d %d %s %t %v\n",
		isd,
		formatSCIONAS(asn),
		localPrefix,
		subnet,
		hostIP,
		hostIsIPv4,
		err,
	)

	// We should get: 64-2:0:9 0 0 129.132.175.104
	//But what we get, (wrong): 64 8589934601 129.132.175.104 <nil>

	// 8589934601 == 0x200000009 == 2:0:9

	// 2:0:9 -> im uint64 = 0x200000009 -> Wenn wir das fmt printen = 8589934601

	/*
			2     : 0     : 9
		0x0002: 0x0000: 0x0009
	*/
}
