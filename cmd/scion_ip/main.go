package main

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.zx2c4.com/wireguard/translator/addr_translation"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: go run ./scion_ip <ISD> <AS> <HOST-IP>\n")
		fmt.Fprintf(os.Stderr, "example: go run ./scion_ip 71 2:0:4a 141.44.25.150\n")
		os.Exit(1)
	}

	isd, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(fmt.Errorf("invalid ISD %q: %w", os.Args[1], err))
	}

	asn, err := addr_translation.ParseASN(os.Args[2])
	if err != nil {
		panic(fmt.Errorf("invalid AS %q: %w", os.Args[2], err))
	}

	host := net.ParseIP(os.Args[3])
	if host == nil {
		panic(fmt.Errorf("invalid host IP %q", os.Args[3]))
	}

	mapped, err := addr_translation.ScionToIP(
		isd,
		asn,
		0,    // localPrefix
		0,    // subnet
		host, // IPv4 or IPv6 host
		8,    // subnetBits
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(addr_translation.FormatSCIONIPv6(mapped))
}

// go run ./cmd/scion_ip 71 20965 141.44.25.150 -> fc04:7051:e500::ffff:8d2c:1996
// go run ./cmd/scion_ip 71 2:0:4a 141.44.25.150 -> fc04:7800:4a00::ffff:8d2c:1996
// fc04:7800:4a00::ffff:8d2c:1996

// The second one is being decoded wrong, i get this as dst: 71-524362
/*
Your ParseASN("2:0:4a") creates this value:
2:0:4a = 0x0002_0000_004a -> compress to 20-bit ASN field.
For colon-style ASNs, your code does:
encodedASN = (1 << 19) | (asn.Value & 0x7ffff)
So:
asn.Value        = 0x20000004a
asn.Value & mask = 0x0004a
flag bit         = 0x80000
encodedASN       = 0x8004a
And:
0x8004a decimal = 524362
*/

// ip address fürs Interface: ip addr show dev wg0
// ip -4 addr show dev wg0 10.44.25.70/32
// ip -6 addr show dev wg0 fd42:42:42::70/128

//SrcHost lokale IP
//DstHost Ipv4 der Website

//71-2:0:4a

// dig +short welcome.scion.host A
// dig +short welcome.scion.host AAAA
// getent ahosts welcome.scion.host
