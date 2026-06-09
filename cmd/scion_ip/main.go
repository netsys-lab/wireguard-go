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

	fmt.Println(mapped.String())
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

//Also diese Adresse: fc04:800:900::ffff:8184:af68
// Sollte wenn ich sie von mir aus schicke, diesen SrcAS haben: 71 2:0:4a
// Und diesen DstAS: 64 2:0:9 und diese IPv4 Dst Adresse: 129.132.175.104
// Dst Adresse ist richtig dekodiert wurde.
//Aber in meinem Logger wird das hier angezeigt:
/*
2026/06/07 09:21:03 [TRANSLATE-EGRESS] Path nextHop: 141.44.25.151:30001
2026/06/07 09:21:03 [TRANSLATE-EGRESS] Host IP from original packet: fd42:42:42::70
2026/06/07 09:21:03 [TRANSLATE-EGRESS] hostIsIPv4: true
2026/06/07 09:21:03 [TRANSLATE-EGRESS] dstHost from To4(): 129.132.175.104
2026/06/07 09:21:03 [TRANSLATE-EGRESS] SrcIA: 71-74
2026/06/07 09:21:03 [TRANSLATE-EGRESS] DstIA: 64-9
*/
//Ich glaube der Code der:
/*
2026/06/07 09:21:03 [TRANSLATE-EGRESS] SrcIA: 71-74
2026/06/07 09:21:03 [TRANSLATE-EGRESS] DstIA: 64-9
*/
// Das Printed ist einfach falsch, den in anderem Konsolen Output ist der Src und Dst AS richtig angegeben:
/*
2026/06/07 09:23:02 [PATHSRV] Path 0: available
2026/06/07 09:23:02 [PATHSRV] Path 1: available
2026/06/07 09:23:02 [PATHSRV] Path 2: available
2026/06/07 09:23:02 [PATHSRV] Path 3: available
2026/06/07 09:23:02 [PATHPOOL] Refresh success: src=71-2:0:4a dst=64-2:0:9 paths=4 reason=timer
DEBUG: (wg0) 2026/06/07 09:23:02 [SCION-PENDING] OnPathReady: src=71-2:0:4a dst=64-2:0:9
2026/06/07 09:23:02 [SCION-PENDING] pop: src=71-2:0:4a dst=64-2:0:9 returned=0 droppedExpired=0
*/
//Das hier wäre der oben erwähnte Code (snippet):
/*
// configDir: The directory containing 'topology.json' and a 'certs' subdirectory.
func NewSciondRetriever(configDir string) (*SciondRetriever, error) {
	log.Printf("[PATHSRV] NewSciondRetriever: configDir=%s", configDir)

	topoPath := filepath.Join(configDir, "topology.json")
	certsDir := filepath.Join(configDir, "certs")

	asInfo, err := daemon.LoadASInfoFromFile(topoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load topology from %s: %w", topoPath, err)
	}

	ia := asInfo.IA()
	mtu := asInfo.MTU()

	log.Printf("[PATHSRV] AS info: IA=%s", ia)
	log.Printf("[PATHSRV] ASInfo MTU=%d", mtu)

	log.Printf("[PATHSRV-CONFIG] topology=%s", topoPath)
	log.Printf("[PATHSRV-CONFIG] certsDir=%s", certsDir)

	rawTopo, err := os.ReadFile(topoPath)
	if err != nil {
		log.Printf("[PATHSRV-CONFIG] failed to read topology raw: %v", err)
	} else {
		log.Printf("[PATHSRV-CONFIG] raw topology.json:\n%s", string(rawTopo))
	}
	logDialChecksFromTopology(topoPath)

	log.Printf("[PATHSRV-CONFIG] asInfo=%+v", asInfo)

*/
