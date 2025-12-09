package header_parsing

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	//slpathscion "github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"

	//"golang.zx2c4.com/wireguard/translator/pathcache"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet/path"
)

//-------------- HELPER ------------------------

func dumpScionHeader(t *testing.T, scionBytes []byte) {
	t.Helper()
	pkt := gopacket.NewPacket(scionBytes, layers.LayerTypeIPv4, gopacket.Default)
	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Logf("no outer UDP layer")
		return
	}
	udp := udpLayer.(*layers.UDP)

	sc := &slayers.SCION{}
	if err := sc.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err != nil {
		t.Logf("SCION decode error: %v", err)
		t.Logf("First 32 bytes of UDP payload: %x", udp.Payload[:min(32, len(udp.Payload))])
		return
	}
	t.Logf("HdrLen=%d, PathType=%v, SrcIA=%s, DstIA=%s", sc.HdrLen, sc.PathType, sc.SrcIA, sc.DstIA)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func mustParseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("invalid IP: %s", s)
	}
	return ip
}

func mustIA(t *testing.T, isd uint16, asn uint32) addr.IA {
	t.Helper()
	ia, err := addr.IAFrom(addr.ISD(isd), addr.AS(asn))
	if err != nil {
		t.Fatalf("IAFrom: %v", err)
	}
	return ia
}

func LoadPackets(t *testing.T, rel string) [][]byte {
	t.Helper()
	fn := filepath.Clean(rel)
	f, err := os.Open(fn)
	if err != nil {
		t.Fatalf("open %s: %v", fn, err)
	}
	defer f.Close()

	var out [][]byte
	for {
		var n uint32
		if err := binary.Read(f, binary.BigEndian, &n); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("read len: %v", err)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(f, buf); err != nil {
			t.Fatalf("read blob: %v", err)
		}
		out = append(out, buf)
	}
	if len(out) == 0 {
		t.Fatalf("no entries in %s", fn)
	}
	return out
}

func loadTestPath(t *testing.T, i int) path.Path {
	t.Helper()

	//Load Raw Paths
	raw := LoadPackets(t, "../data/paths.bin")
	if len(raw) == 0 {
		t.Fatalf("no paths in ../data/paths.bin")
	}

	//Create Next Hops
	var nh *net.UDPAddr
	switch i {
	case 0: //IPv4 ?
		nh = &net.UDPAddr{IP: mustParseIP(t, "127.0.0.9"), Port: 31002}
	case 1: //IPv6 ?
		nh = &net.UDPAddr{IP: mustParseIP(t, "::1"), Port: 31002}
	default:
		t.Fatalf("index out of range: %d", i)
	}

	//srcIA := addr.IA(addr.MustIAFrom(addr.ISD(1), addr.AS(64496)))
	//dstIA := addr.IA(addr.MustIAFrom(addr.ISD(2), addr.AS(64497)))

	srcIA := mustIA(t, 1, 64496)
	dstIA := mustIA(t, 2, 64497)

	meta := snet.PathMetadata{
		MTU: 1280,
		// Interfaces, Latency, etc. can be filled if you care.
	}

	dp := path.SCION{
		Raw: raw[0],
	}

	return path.Path{
		Src:           srcIA,
		Dst:           dstIA,
		DataplanePath: dp,
		NextHop:       nh,
		Meta:          meta,
	}

	/*
		Src           addr.IA
		Dst           addr.IA
		DataplanePath snet.DataplanePath
		NextHop       *net.UDPAddr
		Meta          snet.PathMetadata
	*/

	//snet.Dataplane empty pfad
}

//--------------- Decode -------------------------

func decodeScionUDP(t *testing.T, b []byte) (*slayers.SCION, *layers.UDP, []byte) {
	t.Helper()

	if len(b) == 0 {
		t.Fatalf("empty packet")
	}

	// Detect outer header by first nibble
	firstNibble := b[0] >> 4

	var (
		pkt gopacket.Packet
	)

	switch firstNibble {
	case 4:
		// IPv4 underlay
		pkt = gopacket.NewPacket(b, layers.LayerTypeIPv4, gopacket.Default)
	case 6:
		// IPv6 underlay
		pkt = gopacket.NewPacket(b, layers.LayerTypeIPv6, gopacket.Default)
	default:
		// No IP header
		pkt = gopacket.NewPacket(b, layers.LayerTypeUDP, gopacket.Default)
	}

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatalf("no UDP layer in packet")
	}
	udp := udpLayer.(*layers.UDP)

	// The UDP payload should be the SCION packet
	sc := &slayers.SCION{}
	if err := sc.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err != nil {
		t.Fatalf("failed to decode SCION from UDP payload: %v", err)
	}

	//TODO: We get error here: failed to decode SCION from UDP payload: invalid header, negative pathLen {CmdHdrLen=12; addrHdrLen=24; hdrBytes=8}
	/*
		The UDP payload produced by TranslateEgress is not a valid SCION header
		its common header fields are inconsistent, so the decoder calculates a negative path length and bails out.
	*/

	// scions L4 payload
	payload := append([]byte(nil), sc.Payload...)

	return sc, udp, payload
}

func decodeIPPacket(t *testing.T, b []byte) (*layers.IPv4, *layers.IPv6, *layers.UDP, *layers.TCP, []byte) {
	t.Helper()

	if len(b) == 0 {
		t.Fatalf("empty IP packet")
	}

	firstNibble := b[0] >> 4

	var pkt gopacket.Packet
	switch firstNibble {
	case 4:
		pkt = gopacket.NewPacket(b, layers.LayerTypeIPv4, gopacket.Default)
	case 6:
		pkt = gopacket.NewPacket(b, layers.LayerTypeIPv6, gopacket.Default)
	default:
		t.Fatalf("unsupported IP version nibble: %d", firstNibble)
	}

	var ip4 *layers.IPv4
	var ip6 *layers.IPv6
	var udp *layers.UDP
	var tcp *layers.TCP

	if l := pkt.Layer(layers.LayerTypeIPv4); l != nil {
		ip4 = l.(*layers.IPv4)
	}
	if l := pkt.Layer(layers.LayerTypeIPv6); l != nil {
		ip6 = l.(*layers.IPv6)
	}
	if l := pkt.Layer(layers.LayerTypeUDP); l != nil {
		udp = l.(*layers.UDP)
	}
	if l := pkt.Layer(layers.LayerTypeTCP); l != nil {
		tcp = l.(*layers.TCP)
	}

	var payload []byte
	if app := pkt.ApplicationLayer(); app != nil {
		payload = append([]byte(nil), app.Payload()...)
	}

	return ip4, ip6, udp, tcp, payload
}

//--------------- Compare  -----------------------

func compareScion(t *testing.T, expected, scionBytes []byte) {

	expSC, expUDP, expPayload := decodeScionUDP(t, expected)
	actSC, actUDP, actPayload := decodeScionUDP(t, scionBytes)
	//expSC, expUDP, _ := decodeScionUDP(t, expected)
	//actSC, actUDP, _ := decodeScionUDP(t, scionBytes)

	if expSC.SrcIA != actSC.SrcIA {
		t.Fatalf("SrcIA mismatch: expected %s, got %s", expSC.SrcIA, actSC.SrcIA)
	} else {
		t.Logf("SrcIA match: expected %s, got %s", expSC.SrcIA, actSC.SrcIA)
	}
	if expSC.DstIA != actSC.DstIA {
		t.Fatalf("DstIA mismatch: expected %s, got %s", expSC.DstIA, actSC.DstIA)
	} else {
		t.Logf("DstIA match: expected %s, got %s", expSC.DstIA, actSC.DstIA)
	}
	if expSC.PathType != actSC.PathType {
		t.Fatalf("PathType mismatch: expected %v, got %v", expSC.PathType, actSC.PathType)
	} else {
		t.Logf("DstIA match: expected %s, got %s", expSC.DstIA, actSC.DstIA)
	}
	if expSC.NextHdr != actSC.NextHdr {
		t.Fatalf("NextHdr mismatch: expected %v, got %v", expSC.NextHdr, actSC.NextHdr)
	} else {
		t.Logf("NextHdr match: expected %v, got %v", expSC.NextHdr, actSC.NextHdr)
	}
	if expSC.FlowID != actSC.FlowID {
		//t.Fatalf("FlowID mismatch: expected %d, got %d", expSC.FlowID, actSC.FlowID)
		t.Logf("IGNORING: FlowID mismatch: expected %d, got %d", expSC.FlowID, actSC.FlowID)
	} else {
		t.Logf("FlowID match: expected %d, got %d", expSC.FlowID, actSC.FlowID)
	}
	if expSC.HdrLen != actSC.HdrLen {
		t.Fatalf("HdrLen mismatch: expected %d, got %d", expSC.HdrLen, actSC.HdrLen)
	} else {
		t.Logf("HdrLen match: expected %d, got %d", expSC.HdrLen, actSC.HdrLen)
	}

	if expSC.PayloadLen != actSC.PayloadLen {
		t.Fatalf("PayloadLen mismatch: expected %d, got %d", expSC.PayloadLen, actSC.PayloadLen)
	} else {
		t.Logf("PayloadLen match: expected %d, got %d", expSC.PayloadLen, actSC.PayloadLen)
	}

	//Raw addresses in the scion header
	if !bytes.Equal(expSC.RawSrcAddr, actSC.RawSrcAddr) {
		t.Fatalf("RawSrcAddr mismatch:\nexp=%x\ngot=%x", expSC.RawSrcAddr, actSC.RawSrcAddr)
	} else {
		t.Logf("RawSrcAddr match:\nexp=%x\ngot=%x", expSC.RawSrcAddr, actSC.RawSrcAddr)
	}
	if !bytes.Equal(expSC.RawDstAddr, actSC.RawDstAddr) {
		t.Fatalf("RawDstAddr mismatch:\nexp=%x\ngot=%x", expSC.RawDstAddr, actSC.RawDstAddr)
	} else {
		t.Logf("RawDstAddr match:\nexp=%x\ngot=%x", expSC.RawDstAddr, actSC.RawDstAddr)
	}

	// --- UDP header ---
	if expUDP.SrcPort != actUDP.SrcPort {
		t.Fatalf("UDP SrcPort mismatch: expected %d, got %d", expUDP.SrcPort, actUDP.SrcPort)
	} else {
		t.Logf("UDP SrcPort match: expected %d, got %d", expUDP.SrcPort, actUDP.SrcPort)
	}
	if expUDP.DstPort != actUDP.DstPort {
		t.Fatalf("UDP DstPort mismatch: expected %d, got %d", expUDP.DstPort, actUDP.DstPort)
	} else {
		t.Logf("UDP DstPort match: expected %d, got %d", expUDP.DstPort, actUDP.DstPort)
	}
	if expUDP.Length != actUDP.Length {
		t.Fatalf("UDP Length mismatch: expected %d, got %d", expUDP.Length, actUDP.Length)
	} else {
		t.Logf("UDP Length match: expected %d, got %d", expUDP.Length, actUDP.Length)
	}
	if expSC.TrafficClass != actSC.TrafficClass {
		t.Fatalf("TrafficClass mismatch: expected %d, got %d", expUDP.Length, actUDP.Length)
	} else {
		t.Logf("TrafficClass match: expected %d, got %d", expUDP.Length, actUDP.Length)
	}

	// --- L4 payload ---
	if !bytes.Equal(expPayload, actPayload) {
		t.Fatalf("UDP payload mismatch:\nexp=%x\ngot=%x", expPayload, actPayload)
	} else {
		t.Logf("UDP payload match:\nexp=%x\ngot=%x", expPayload, actPayload)
	}

	// checksum
	if expUDP.Checksum != actUDP.Checksum {
		t.Fatalf("UDP Checksum mismatch: expected 0x%04x, got 0x%04x",
			expUDP.Checksum, actUDP.Checksum)
	} else {
		t.Logf("UDP Checksum match: expected 0x%04x, got 0x%04x",
			expUDP.Checksum, actUDP.Checksum)
	}

}

/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version| TrafficClass  |                FlowID                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    NextHdr    |    HdrLen     |          PayloadLen           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    PathType   |DT |DL |ST |SL |              RSV              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/*
Underlay Network (IP/UDP)
-----------------------------------
IPv4 or IPv6 underlay      ← optional
UDP underlay                ← port = 30041 or similar
-----------------------------------
SCION Header
SCION Path
SCION Address Fields
-----------------------------------
L4 Payload
  ├─ SCION-UDP
  ├─ SCMP (ICMP of SCION)
  ├─ SCION-TCP (rare)
  └─ custom protocol
-----------------------------------
Application Payload (“TEST”)
*/

/*
	IPv4 (Underlay)
    └─ UDP (Underlay)
         └─ SCION Header
              ├─ Common Header
              ├─ Address Header (SrcIA, DstIA, Host Addrs)
              ├─ Path Header (Paths, InfoFields, HopFields)
              └─ L4 Header (SCION-UDP / SCMP / TCP)
                   └─ Payload
*/

//Difference in the Bytes
/*
expected: 452000d4000040004011b0ef0a0000017f0000097ffe791a00c00eac02086c8b112b000c01000000000200000000fbf1000100000000fbf00a0000020a000001880030840000000167e29ac00100000267e2a8d00100000367e2b6e00000000400000000000000000000000200030000000000000000000000010000000000000000000000050000000000000000000600000000000000000000000000070000000000000000000800090000000000000000000a000b0000000000000000000c00000000000000007ffe7fff000c4c5654455354
scion: 450000d4000000004011f10f0a0000017f0000097ffe791a00c00eac02086c8b112b000c01000000000200000000fbf1000100000000fbf00a0000020a000001880030840000000167e29ac00100000267e2a8d00100000367e2b6e00000000400000000000000000000000200030000000000000000000000010000000000000000000000050000000000000000000600000000000000000000000000070000000000000000000800090000000000000000000a000b0000000000000000000c00000000000000007ffe7fff000c4c5654455354
Decode the IPv4 header fields:
Byte 0: 0x45 – Version + IHL (same)
Byte 1: TOS expected: 0x20got: 0x00
Bytes 2–3: Total length = 0x00d4 (same)
Bytes 4–5: ID = 0x0000 (same)
Bytes 6–7: Flags + Fragment offset expected: 0x4000 (DF bit set, offset 0) got: 0x0000 (no flags)
Byte 8: TTL = 0x40 (64) (same)
Byte 9: Protocol = 0x11 (UDP) (same)
Bytes 10–11: checksum (differs because header content differs)
Src/Dst IP: 0a000001 / 7f000009 (same)
*/

func compareIP(t *testing.T, expected, actual []byte) {
	t.Helper()

	exp4, exp6, expUDP, expTCP, expPayload := decodeIPPacket(t, expected)
	act4, act6, actUDP, actTCP, actPayload := decodeIPPacket(t, actual)

	// -------- IP version / header --------
	// -------- Payload --------
	if !bytes.Equal(expPayload, actPayload) {
		t.Fatalf("L4 payload mismatch:\nexp=%x\ngot=%x", expPayload, actPayload)
	} else {
		t.Logf("L4 payload match:\nexp=%x\ngot=%x", expPayload, actPayload)
	}

	switch {
	case exp4 != nil && act4 != nil:
		// IPv4 comparison
		if exp4.Version != act4.Version {
			t.Fatalf("IPv4 Version mismatch: expected %d, got %d", exp4.Version, act4.Version)
		} else {
			t.Logf("IPv4 Version match: %d", exp4.Version)
		}

		if exp4.IHL != act4.IHL {
			t.Fatalf("IPv4 IHL mismatch: expected %d, got %d", exp4.IHL, act4.IHL)
		} else {
			t.Logf("IPv4 IHL match: %d", exp4.IHL)
		}

		if exp4.TOS != act4.TOS {
			t.Fatalf("IPv4 TOS mismatch: expected %d, got %d", exp4.TOS, act4.TOS)
		} else {
			t.Logf("IPv4 TOS match: %d", exp4.TOS)
		}

		if exp4.Flags != act4.Flags {
			t.Fatalf("IPv4 Flags mismatch: expected %v, got %v", exp4.Flags, act4.Flags)
		} else {
			t.Logf("IPv4 Flags match: %v", exp4.Flags)
		}

		if exp4.FragOffset != act4.FragOffset {
			t.Fatalf("IPv4 FragOffset mismatch: expected %d, got %d", exp4.FragOffset, act4.FragOffset)
		} else {
			t.Logf("IPv4 FragOffset match: %d", exp4.FragOffset)
		}

		if exp4.TTL != act4.TTL {
			t.Fatalf("IPv4 TTL mismatch: expected %d, got %d", exp4.TTL, act4.TTL)
		} else {
			t.Logf("IPv4 TTL match: %d", exp4.TTL)
		}

		if exp4.Protocol != act4.Protocol {
			t.Fatalf("IPv4 Protocol mismatch: expected %d, got %d", exp4.Protocol, act4.Protocol)
		} else {
			t.Logf("IPv4 Protocol match: %d", exp4.Protocol)
		}

		if !exp4.SrcIP.Equal(act4.SrcIP) {
			t.Fatalf("IPv4 SrcIP mismatch: expected %s, got %s", exp4.SrcIP, act4.SrcIP)
		} else {
			t.Logf("IPv4 SrcIP match: %s", exp4.SrcIP)
		}
		if !exp4.DstIP.Equal(act4.DstIP) {
			t.Fatalf("IPv4 DstIP mismatch: expected %s, got %s", exp4.DstIP, act4.DstIP)
		} else {
			t.Logf("IPv4 DstIP match: %s", exp4.DstIP)
		}

		// Header checksum
		if exp4.Checksum != act4.Checksum {
			t.Fatalf("IPv4 Checksum mismatch: expected 0x%04x, got 0x%04x",
				exp4.Checksum, act4.Checksum)
		} else {
			t.Logf("IPv4 Checksum match: 0x%04x", exp4.Checksum)
		}

	case exp6 != nil && act6 != nil:
		// IPv6 comparison
		if exp6.Version != act6.Version {
			t.Fatalf("IPv6 Version mismatch: expected %d, got %d", exp6.Version, act6.Version)
		} else {
			t.Logf("IPv6 Version match: %d", exp6.Version)
		}

		if exp6.TrafficClass != act6.TrafficClass {
			t.Fatalf("IPv6 TrafficClass mismatch: expected %d, got %d", exp6.TrafficClass, act6.TrafficClass)
		} else {
			t.Logf("IPv6 TrafficClass match: %d", exp6.TrafficClass)
		}

		if exp6.FlowLabel != act6.FlowLabel {
			t.Fatalf("IPv6 FlowLabel mismatch: expected %d, got %d", exp6.FlowLabel, act6.FlowLabel)
		} else {
			t.Logf("IPv6 FlowLabel match: %d", exp6.FlowLabel)
		}

		if exp6.NextHeader != act6.NextHeader {
			t.Fatalf("IPv6 NextHeader mismatch: expected %d, got %d", exp6.NextHeader, act6.NextHeader)
		} else {
			t.Logf("IPv6 NextHeader match: %d", exp6.NextHeader)
		}

		if exp6.HopLimit != act6.HopLimit {
			t.Fatalf("IPv6 HopLimit mismatch: expected %d, got %d", exp6.HopLimit, act6.HopLimit)
		} else {
			t.Logf("IPv6 HopLimit match: %d", exp6.HopLimit)
		}

		if !exp6.SrcIP.Equal(act6.SrcIP) {
			t.Fatalf("IPv6 SrcIP mismatch: expected %s, got %s", exp6.SrcIP, act6.SrcIP)
		} else {
			t.Logf("IPv6 SrcIP match: %s", exp6.SrcIP)
		}
		if !exp6.DstIP.Equal(act6.DstIP) {
			t.Fatalf("IPv6 DstIP mismatch: expected %s, got %s", exp6.DstIP, act6.DstIP)
		} else {
			t.Logf("IPv6 DstIP match: %s", exp6.DstIP)
		}

	default:
		t.Fatalf("IP version mismatch or missing IP header (expected v4=%v v6=%v, got v4=%v v6=%v)",
			exp4 != nil, exp6 != nil, act4 != nil, act6 != nil)
	}

	// -------- UDP / TCP --------

	// UDP if present
	if expUDP != nil || actUDP != nil {
		if expUDP == nil || actUDP == nil {
			t.Fatalf("UDP presence mismatch: expected %v, got %v", expUDP != nil, actUDP != nil)
		}

		if expUDP.SrcPort != actUDP.SrcPort {
			t.Fatalf("UDP SrcPort mismatch: expected %d, got %d", expUDP.SrcPort, actUDP.SrcPort)
		} else {
			t.Logf("UDP SrcPort match: %d", expUDP.SrcPort)
		}

		if expUDP.DstPort != actUDP.DstPort {
			t.Fatalf("UDP DstPort mismatch: expected %d, got %d", expUDP.DstPort, actUDP.DstPort)
		} else {
			t.Logf("UDP DstPort match: %d", expUDP.DstPort)
		}

		if expUDP.Length != actUDP.Length {
			t.Fatalf("UDP Length mismatch: expected %d, got %d", expUDP.Length, actUDP.Length)
		} else {
			t.Logf("UDP Length match: %d", expUDP.Length)
		}

		if expUDP.Checksum != actUDP.Checksum {
			t.Fatalf("UDP Checksum mismatch: expected 0x%04x, got 0x%04x",
				expUDP.Checksum, actUDP.Checksum)
		} else {
			t.Logf("UDP Checksum match: 0x%04x", expUDP.Checksum)
		}
	}

	// TCP if present
	if expTCP != nil || actTCP != nil {
		if expTCP == nil || actTCP == nil {
			t.Fatalf("TCP presence mismatch: expected %v, got %v", expTCP != nil, actTCP != nil)
		}

		if expTCP.SrcPort != actTCP.SrcPort {
			t.Fatalf("TCP SrcPort mismatch: expected %d, got %d", expTCP.SrcPort, actTCP.SrcPort)
		} else {
			t.Logf("TCP SrcPort match: %d", expTCP.SrcPort)
		}

		if expTCP.DstPort != actTCP.DstPort {
			t.Fatalf("TCP DstPort mismatch: expected %d, got %d", expTCP.DstPort, actTCP.DstPort)
		} else {
			t.Logf("TCP DstPort match: %d", expTCP.DstPort)
		}

		if expTCP.Seq != actTCP.Seq {
			t.Fatalf("TCP Seq mismatch: expected %d, got %d", expTCP.Seq, actTCP.Seq)
		} else {
			t.Logf("TCP Seq match: %d", expTCP.Seq)
		}

		if expTCP.Ack != actTCP.Ack {
			t.Fatalf("TCP Ack mismatch: expected %d, got %d", expTCP.Ack, actTCP.Ack)
		} else {
			t.Logf("TCP Ack match: %d", expTCP.Ack)
		}

		if expTCP.Window != actTCP.Window {
			t.Fatalf("TCP Window mismatch: expected %d, got %d", expTCP.Window, actTCP.Window)
		} else {
			t.Logf("TCP Window match: %d", expTCP.Window)
		}

		if expTCP.Checksum != actTCP.Checksum {
			t.Fatalf("TCP Checksum mismatch: expected 0x%04x, got 0x%04x",
				expTCP.Checksum, actTCP.Checksum)
		} else {
			t.Logf("TCP Checksum match: 0x%04x", expTCP.Checksum)
		}

	}

}

//--------------- Tests ------------------------

// ---------------- UDP -------------------------
func TestTranslateIpUdpToScion4(t *testing.T) {
	/*
		Translate UDP/IPv6 to UDP/SCION with a UDP/IPv4 underlay.
	*/

	// Load Packets
	pkts := LoadPackets(t, "../data/translate_udp_ipv4.bin")

	// Input
	input := pkts[0]

	// Expected
	expected := pkts[1]

	// Translator
	translator := NewTranslator(nil)

	// HostIP
	hostIP := mustParseIP(t, "10.0.0.1")

	//IA
	//srcIA := mustIA(t, 1, 64496)
	//dstIA := mustIA(t, 2, 64497)

	//GetPathCallback
	GetPathCallback := func(srcIA, dstIA addr.IA) (path.Path, error) {
		fake := loadTestPath(t, 0)
		return fake, nil
	}

	scionBytes, _, err := translator.TranslateEgress(input, hostIP, 32766, GetPathCallback)
	if err != nil {
		t.Fatalf("Error in TranslateEgress: %s", err)
	}

	//------------------- Quick ScionHeaderDump
	dumpScionHeader(t, scionBytes)

	//------------------- Compare
	compareScion(t, expected, scionBytes)

	//------------------- Assertions
	if !bytes.Equal(scionBytes, expected) {
		t.Fatalf("SCION Bytes mismatch: \nexpected: %x\nscion: %x", expected, scionBytes)
	}

}

func TestTranslateScion4ToIpUdp(t *testing.T) {
	/*
		Translate UDP/SCION with a UDP/IPv4 underlay to UDP/IPv6.
	*/

	// Load Packets
	pkts := LoadPackets(t, "../data/translate_udp_ipv4.bin")

	// Input
	input := pkts[1]

	// Expected
	expected := pkts[0]

	// Translator
	translator := NewTranslator(nil)

	// HostIP
	hostIP := mustParseIP(t, "fc00:10fb:f000::ffff:a00:1")

	//IA
	//srcIA := mustIA(t, 1, 64496)
	//dstIA := mustIA(t, 2, 64497)

	ipBytes, err := translator.TranslateIngress(input, hostIP)
	if err != nil {
		t.Fatalf("Error in TranslateEgress: %s", err)
	}

	//------------------- Quick ScionHeaderDump
	//dumpScionHeader(t, scionBytes)

	//------------------- Compare
	compareIP(t, expected, ipBytes)

	//------------------- Assertions
	if !bytes.Equal(ipBytes, expected) {
		t.Fatalf("IPv6 Bytes mismatch: \nexpected: %x\nipv6: %x", expected, ipBytes)
	}
}

func TestTranslateIpUdpToScion4Local(t *testing.T) {
	/*
		Translate UDP/IPv6 to UDP/SCION with a UDP/IPv4 underlay and an empty path.
	*/

	// Load Packets
	pkts := LoadPackets(t, "../data/translate_udp_ipv4_local.bin")

	// Input
	input := pkts[0]

	// Expected
	expected := pkts[1]

	// Translator
	translator := NewTranslator(nil)

	// HostIP
	hostIP := mustParseIP(t, "10.0.0.1")

	//IA
	//srcIA := mustIA(t, 1, 64496)
	//dstIA := mustIA(t, 2, 64497)

	//GetPathCallback
	GetPathCallback := func(srcIA, dstIA addr.IA) (path.Path, error) {
		//fake := loadTestPath(t, 0)
		return path.Path{}, nil
	}

	scionBytes, _, err := translator.TranslateEgress(input, hostIP, 32766, GetPathCallback)
	if err != nil {
		t.Fatalf("Error in TranslateEgress: %s", err)
	}

	//------------------- Quick ScionHeaderDump
	dumpScionHeader(t, scionBytes)

	//------------------- Compare
	compareScion(t, expected, scionBytes)

	//------------------- Assertions
	if !bytes.Equal(scionBytes, expected) {
		t.Fatalf("SCION Bytes mismatch: \nexpected: %x\nscion: %x", expected, scionBytes)
	}

}

func TestTranslateScion6ToIpUdp(t *testing.T) {
	/*
		Translate UDP/SCION with a UDP/IPv6 underlay to UDP/IPv6.
	*/

	// Load Packets
	pkts := LoadPackets(t, "../data/translate_udp_ipv6.bin")

	// Input
	input := pkts[1]

	// Expected
	expected := pkts[0]

	// Translator
	translator := NewTranslator(nil)

	// HostIP
	hostIP := mustParseIP(t, "fc00:10fb:f000::1")

	//IA
	//srcIA := mustIA(t, 1, 64496)
	//dstIA := mustIA(t, 2, 64497)

	ipBytes, err := translator.TranslateIngress(input, hostIP)
	if err != nil {
		t.Fatalf("Error in TranslateEgress: %s", err)
	}

	//------------------- Quick ScionHeaderDump
	//dumpScionHeader(t, ipBytes)

	//------------------- Compare
	compareIP(t, expected, ipBytes)

	//------------------- Assertions
	if !bytes.Equal(ipBytes, expected) {
		t.Fatalf("IPv6 Bytes mismatch: \nexpected: %x\nipv6: %x", expected, ipBytes)
	} else {
		t.Logf("IPv6 Bytes mismatch: \nexpected: %x\nipv6: %x", expected, ipBytes)
	}

}

func TestTranslateIpUdpToScion6(t *testing.T) {
	/*
		// Translate UDP/IPv6 to UDP/SCION with a UDP/IPv6 underlay.
	*/

	// Load Packets
	pkts := LoadPackets(t, "../data/translate_udp_ipv6.bin")

	// Input
	input := pkts[0]

	// Expected
	expected := pkts[1]

	// Translator
	translator := NewTranslator(nil)

	// HostIP
	hostIP := mustParseIP(t, "fc00:10fb:f000::1")

	//IA
	//srcIA := mustIA(t, 1, 64496)
	//dstIA := mustIA(t, 2, 64497)

	//GetPathCallback
	GetPathCallback := func(srcIA, dstIA addr.IA) (path.Path, error) {
		fake := loadTestPath(t, 1)
		return fake, nil
	}

	scionBytes, _, err := translator.TranslateEgress(input, hostIP, 32766, GetPathCallback)
	if err != nil {
		t.Fatalf("Error in TranslateEgress: %s", err)
	}

	//------------------- Quick ScionHeaderDump
	dumpScionHeader(t, scionBytes)

	//------------------- Compare
	compareScion(t, expected, scionBytes)

	//------------------- Assertions
	if !bytes.Equal(scionBytes, expected) {
		t.Fatalf("SCION Bytes mismatch: \nexpected: %x\nscion: %x", expected, scionBytes)
	}

}

func TestTranslateIpUdpToScion6Local(t *testing.T) {
	/*
		Translate UDP/IPv6 to UDP/SCION with a UDP/IPv6 underlay and an empty path.
	*/
	// Load Packets
	pkts := LoadPackets(t, "../data/translate_udp_ipv6_local.bin")

	// Input
	input := pkts[0]

	// Expected
	expected := pkts[1]

	// Translator
	translator := NewTranslator(nil)

	// HostIP
	hostIP := mustParseIP(t, "fc00:10fb:f000::1")

	//IA
	//srcIA := mustIA(t, 1, 64496)
	//dstIA := mustIA(t, 2, 64497)

	//GetPathCallback
	GetPathCallback := func(srcIA, dstIA addr.IA) (path.Path, error) {
		//fake := loadTestPath(t, 1)
		return path.Path{}, nil
	}

	scionBytes, _, err := translator.TranslateEgress(input, hostIP, 32766, GetPathCallback)
	if err != nil {
		t.Fatalf("Error in TranslateEgress: %s", err)
	}

	//------------------- Quick ScionHeaderDump
	dumpScionHeader(t, scionBytes)

	//------------------- Compare
	compareScion(t, expected, scionBytes)

	//------------------- Assertions
	if !bytes.Equal(scionBytes, expected) {
		t.Fatalf("SCION Bytes mismatch: \nexpected: %x\nscion: %x", expected, scionBytes)
	}

}

//---------------- TCP -------------------------

func TestTranslateIpTcpToScion4(t *testing.T) {
	/*
		Translate TCP/IPv6 to TCP/SCION with a UDP/IPv4 underlay.
	*/

	// Load Packets
	pkts := LoadPackets(t, "../data/translate_tcp_ipv4.bin")

	// Input
	input := pkts[0]

	// Expected
	expected := pkts[2]

	// Translator
	translator := NewTranslator(nil)

	// HostIP
	hostIP := mustParseIP(t, "10.0.0.1")

	//IA
	//srcIA := mustIA(t, 1, 64496)
	//dstIA := mustIA(t, 2, 64497)

	//GetPathCallback
	GetPathCallback := func(srcIA, dstIA addr.IA) (path.Path, error) {
		fake := loadTestPath(t, 0)
		return fake, nil
	}

	scionBytes, _, err := translator.TranslateEgress(input, hostIP, 32766, GetPathCallback)
	if err != nil {
		t.Fatalf("Error in TranslateEgress: %s", err)
	}

	//------------------- Quick ScionHeaderDump
	//dumpScionHeader(t, scionBytes)

	//------------------- Compare
	compareScion(t, expected, scionBytes)

	//------------------- Assertions
	if !bytes.Equal(scionBytes, expected) {
		t.Fatalf("SCION Bytes mismatch: \nexpected: %x\nscion: %x", expected, scionBytes)
	}

}

func TestTranslateScion4ToIpTcp(t *testing.T) {
	/*
		Translate TCP/SCION with a UDP/IPv4 underlay to TCP/IPv6.
	*/

	// Load Packets
	pkts := LoadPackets(t, "../data/translate_tcp_ipv4.bin")

	// Input
	input := pkts[2]

	// Expected
	expected := pkts[0]

	// Translator
	translator := NewTranslator(nil)

	// HostIP
	hostIP := mustParseIP(t, "fc00:20fb:f100::ffff:a00:2")

	//IA
	//srcIA := mustIA(t, 1, 64496)
	//dstIA := mustIA(t, 2, 64497)

	ipBytes, err := translator.TranslateIngress(input, hostIP)
	if err != nil {
		t.Fatalf("Error in TranslateEgress: %s", err)
	}

	//------------------- Quick ScionHeaderDump
	//dumpScionHeader(t, scionBytes)

	//------------------- Compare
	compareIP(t, expected, ipBytes)

	//------------------- Assertions
	if !bytes.Equal(ipBytes, expected) {
		t.Fatalf("SCION Bytes mismatch: \nexpected: %x\nscion: %x", expected, ipBytes)
	}

}

func TestTranslation(t *testing.T) {

	//-------------------------- WORKING TESTS ----------------------------

	//Translate UDP/SCION with a UDP/IPv4 underlay to UDP/IPv6.
	TestTranslateIpUdpToScion4(t)

	// Translate UDP/SCION with a UDP/IPv4 underlay to UDP/IPv6.
	TestTranslateScion4ToIpUdp(t)

	// Translate UDP/IPv6 to UDP/SCION with a UDP/IPv4 underlay and an empty path.
	TestTranslateIpUdpToScion4Local(t)

	// Translate UDP/SCION with a UDP/IPv4 underlay and an empty path to UDP/IPv6.
	//TestTranslateScion4ToIpUdpLocal(t)

	// Translate UDP/IPv6 to UDP/SCION with a UDP/IPv6 underlay.
	TestTranslateIpUdpToScion6(t)

	// Translate UDP/SCION with a UDP/IPv6 underlay to UDP/IPv6.
	TestTranslateScion6ToIpUdp(t)

	// Translate UDP/IPv6 to UDP/SCION with a UDP/IPv6 underlay and an empty path.
	TestTranslateIpUdpToScion6Local(t)

	// Translate UDP/SCION with a UDP/IPv6 underlay and an empty path to UDP/IPv6.
	//TestTranslateScion6ToIpUdpLocal(t)

	// Translate UDP/IPv6 to UDP/SCION without an underlay.
	//

	// Translate UDP/SCION without an underlay to UDP/IPv6.
	//

	// Translate TCP/IPv6 to TCP/SCION with a UDP/IPv4 underlay.
	TestTranslateIpTcpToScion4(t)

	// Translate TCP/SCION with a UDP/IPv4 underlay to TCP/IPv6.
	TestTranslateScion4ToIpTcp(t)

	// Translate ICMP/IPv6 to SCMP/SCION with a UDP/IPv4 underlay.
	//TestTranslateIcmpToScmp(t)

	// Translate SCMP/SCION with a UDP/IPv4 underlay to ICMP/IPv6.
	//TestTranslateScmpToIcmp(t)

	// Test ICMP Packet Too Big response
	//TestRespondPacketTooBig(t)

	// Test ICMP Packet Destination Unreachable (Address UNreachable) response
	//TestRespondAddressUnreachable(t)

	// Test ICMP Packet Destination Unreachable (No Route) response
	//TestRespondNoRouteToDestination(t)

}
