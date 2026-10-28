package header_parsing

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// helper to build a test IPv6+TCP packet using gopacket
func buildTestIPv6TCP(opts []layers.TCPOption, payload []byte, syn, ack bool) []byte {
	buf := gopacket.NewSerializeBuffer()
	ip6 := &layers.IPv6{
		Version:      6,
		TrafficClass: 0x42,
		FlowLabel:    0x12345,
		NextHeader:   layers.IPProtocolTCP,
		HopLimit:     64,
		SrcIP:        net.ParseIP("2001:db8::1"),
		DstIP:        net.ParseIP("fc00:f00d:cafe:42::1"),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(80),
		Seq:     1000,
		Ack:     2000,
		SYN:     syn,
		ACK:     ack,
		PSH:     true,
		Window:  65535,
		Options: opts,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip6)
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, ip6, tcp, gopacket.Payload(payload))
	return buf.Bytes()
}

// helper to build a test IPv6+UDP packet using gopacket
func buildTestIPv6UDP(payload []byte) []byte {
	buf := gopacket.NewSerializeBuffer()
	ip6 := &layers.IPv6{
		Version:      6,
		TrafficClass: 0x20,
		FlowLabel:    0xABCDE,
		NextHeader:   layers.IPProtocolUDP,
		HopLimit:     64,
		SrcIP:        net.ParseIP("2001:db8::2"),
		DstIP:        net.ParseIP("fc00:f00d:cafe:42::2"),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(54321),
		DstPort: layers.UDPPort(443),
	}
	_ = udp.SetNetworkLayerForChecksum(ip6)
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, ip6, udp, gopacket.Payload(payload))
	return buf.Bytes()
}

// helper to build IPv6 packet with Hop-by-Hop extension header
func buildTestIPv6HopByHopTCP(payload []byte) []byte {
	pktLen := 40 + 8 + 20 + len(payload)
	pkt := make([]byte, pktLen)
	// IPv6 Base Header
	pkt[0] = 0x60 // IPv6, TC=0
	binary.BigEndian.PutUint16(pkt[4:6], uint16(8+20+len(payload)))
	pkt[6] = 0 // NextHeader = Hop-by-Hop
	pkt[7] = 64
	copy(pkt[8:24], net.ParseIP("2001:db8::3").To16())
	copy(pkt[24:40], net.ParseIP("fc00:f00d:cafe:42::3").To16())

	// Hop-by-Hop Header (8 bytes)
	pkt[40] = 6 // NextHeader in HBH = TCP
	pkt[41] = 0 // HdrExtLen (0 = 8 bytes total)
	// bytes 42..47 are zero / PadN

	// TCP Header (20 bytes)
	binary.BigEndian.PutUint16(pkt[48:50], 8080) // SrcPort
	binary.BigEndian.PutUint16(pkt[50:52], 9090) // DstPort
	binary.BigEndian.PutUint32(pkt[52:56], 500)  // Seq
	binary.BigEndian.PutUint32(pkt[56:60], 600)  // Ack
	pkt[60] = 0x50                              // DataOffset = 5 (20 bytes)
	pkt[61] = 0x10                              // ACK
	binary.BigEndian.PutUint16(pkt[62:64], 32768)

	// Payload
	copy(pkt[68:], payload)
	return pkt
}

func TestFastParser_TCP_Parity(t *testing.T) {
	opts := []layers.TCPOption{
		{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x05, 0xB4}, // MSS = 1460
		},
		{
			OptionType:   layers.TCPOptionKindWindowScale,
			OptionLength: 3,
			OptionData:   []byte{0x07},
		},
		{
			OptionType:   layers.TCPOptionKindSACKPermitted,
			OptionLength: 2,
		},
		{
			OptionType:   layers.TCPOptionKindNop,
			OptionLength: 1,
		},
	}
	payload := []byte("Hello, Scintra fast-path TCP world!")
	rawPkt := buildTestIPv6TCP(opts, payload, true, true)

	// 1. Gopacket baseline
	goPkt := gopacket.NewPacket(rawPkt, layers.LayerTypeIPv6, gopacket.Default)
	goIP6 := goPkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	goTCP := goPkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	var goPayload []byte
	if app := goPkt.ApplicationLayer(); app != nil {
		goPayload = app.Payload()
	}

	// 2. FastParser
	fastPkt, err := ParseEgressPacket(rawPkt)
	if err != nil {
		t.Fatalf("ParseEgressPacket failed: %v", err)
	}
	defer fastPkt.Release()

	if !fastPkt.IsFastPath {
		t.Fatalf("Expected IsFastPath=true for direct IPv6+TCP packet")
	}

	// Verify IPv6 fields parity
	if fastPkt.IPv6.Version != goIP6.Version {
		t.Errorf("IPv6 Version mismatch: fast=%d, gopacket=%d", fastPkt.IPv6.Version, goIP6.Version)
	}
	if fastPkt.IPv6.TrafficClass != goIP6.TrafficClass {
		t.Errorf("TrafficClass mismatch: fast=%d, gopacket=%d", fastPkt.IPv6.TrafficClass, goIP6.TrafficClass)
	}
	if fastPkt.IPv6.FlowLabel != goIP6.FlowLabel {
		t.Errorf("FlowLabel mismatch: fast=0x%x, gopacket=0x%x", fastPkt.IPv6.FlowLabel, goIP6.FlowLabel)
	}
	if fastPkt.IPv6.PayloadLen != goIP6.Length {
		t.Errorf("PayloadLen mismatch: fast=%d, gopacket=%d", fastPkt.IPv6.PayloadLen, goIP6.Length)
	}
	if fastPkt.IPv6.NextHeader != goIP6.NextHeader {
		t.Errorf("NextHeader mismatch: fast=%v, gopacket=%v", fastPkt.IPv6.NextHeader, goIP6.NextHeader)
	}
	if fastPkt.IPv6.HopLimit != goIP6.HopLimit {
		t.Errorf("HopLimit mismatch: fast=%d, gopacket=%d", fastPkt.IPv6.HopLimit, goIP6.HopLimit)
	}
	if !fastPkt.IPv6.SrcIP.Equal(goIP6.SrcIP) {
		t.Errorf("SrcIP mismatch: fast=%s, gopacket=%s", fastPkt.IPv6.SrcIP, goIP6.SrcIP)
	}
	if !fastPkt.IPv6.DstIP.Equal(goIP6.DstIP) {
		t.Errorf("DstIP mismatch: fast=%s, gopacket=%s", fastPkt.IPv6.DstIP, goIP6.DstIP)
	}

	// Verify TCP fields parity
	tcp := fastPkt.TCP
	if tcp == nil {
		t.Fatalf("fastPkt.TCP is nil")
	}
	if tcp.SrcPort != goTCP.SrcPort {
		t.Errorf("TCP SrcPort mismatch: fast=%d, gopacket=%d", tcp.SrcPort, goTCP.SrcPort)
	}
	if tcp.DstPort != goTCP.DstPort {
		t.Errorf("TCP DstPort mismatch: fast=%d, gopacket=%d", tcp.DstPort, goTCP.DstPort)
	}
	if tcp.Seq != goTCP.Seq {
		t.Errorf("TCP Seq mismatch: fast=%d, gopacket=%d", tcp.Seq, goTCP.Seq)
	}
	if tcp.Ack != goTCP.Ack {
		t.Errorf("TCP Ack mismatch: fast=%d, gopacket=%d", tcp.Ack, goTCP.Ack)
	}
	if tcp.DataOffset != goTCP.DataOffset {
		t.Errorf("TCP DataOffset mismatch: fast=%d, gopacket=%d", tcp.DataOffset, goTCP.DataOffset)
	}
	if tcp.SYN != goTCP.SYN || tcp.ACK != goTCP.ACK || tcp.PSH != goTCP.PSH {
		t.Errorf("TCP flags mismatch: fast=(SYN:%v, ACK:%v, PSH:%v), gopacket=(SYN:%v, ACK:%v, PSH:%v)",
			tcp.SYN, tcp.ACK, tcp.PSH, goTCP.SYN, goTCP.ACK, goTCP.PSH)
	}
	if tcp.Window != goTCP.Window {
		t.Errorf("TCP Window mismatch: fast=%d, gopacket=%d", tcp.Window, goTCP.Window)
	}
	if tcp.Checksum != goTCP.Checksum {
		t.Errorf("TCP Checksum mismatch: fast=0x%x, gopacket=0x%x", tcp.Checksum, goTCP.Checksum)
	}
	if len(tcp.Options) != len(goTCP.Options) {
		t.Errorf("TCP Options length mismatch: fast=%d, gopacket=%d", len(tcp.Options), len(goTCP.Options))
	} else {
		for i := range tcp.Options {
			if tcp.Options[i].OptionType != goTCP.Options[i].OptionType {
				t.Errorf("Option[%d] Type mismatch: fast=%v, gopacket=%v", i, tcp.Options[i].OptionType, goTCP.Options[i].OptionType)
			}
			if !bytes.Equal(tcp.Options[i].OptionData, goTCP.Options[i].OptionData) {
				t.Errorf("Option[%d] Data mismatch: fast=%x, gopacket=%x", i, tcp.Options[i].OptionData, goTCP.Options[i].OptionData)
			}
		}
	}

	// Verify payload parity
	if !bytes.Equal(fastPkt.Payload, goPayload) {
		t.Errorf("Payload mismatch:\nfast:     %q\ngopacket: %q", string(fastPkt.Payload), string(goPayload))
	}
}

func TestFastParser_UDP_Parity(t *testing.T) {
	payload := []byte("Scintra fast-path UDP payload data 1234567890")
	rawPkt := buildTestIPv6UDP(payload)

	// 1. Gopacket baseline
	goPkt := gopacket.NewPacket(rawPkt, layers.LayerTypeIPv6, gopacket.Default)
	goIP6 := goPkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	goUDP := goPkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	var goPayload []byte
	if app := goPkt.ApplicationLayer(); app != nil {
		goPayload = app.Payload()
	}

	// 2. FastParser
	fastPkt, err := ParseEgressPacket(rawPkt)
	if err != nil {
		t.Fatalf("ParseEgressPacket failed: %v", err)
	}
	defer fastPkt.Release()

	if !fastPkt.IsFastPath {
		t.Fatalf("Expected IsFastPath=true for direct IPv6+UDP packet")
	}

	// IPv6 Parity
	if fastPkt.IPv6.TrafficClass != goIP6.TrafficClass {
		t.Errorf("TrafficClass mismatch: fast=%d, gopacket=%d", fastPkt.IPv6.TrafficClass, goIP6.TrafficClass)
	}
	if fastPkt.IPv6.FlowLabel != goIP6.FlowLabel {
		t.Errorf("FlowLabel mismatch: fast=0x%x, gopacket=0x%x", fastPkt.IPv6.FlowLabel, goIP6.FlowLabel)
	}
	if !fastPkt.IPv6.SrcIP.Equal(goIP6.SrcIP) || !fastPkt.IPv6.DstIP.Equal(goIP6.DstIP) {
		t.Errorf("IP mismatch")
	}

	// UDP Parity
	if fastPkt.SrcPort != uint16(goUDP.SrcPort) {
		t.Errorf("UDP SrcPort mismatch: fast=%d, gopacket=%d", fastPkt.SrcPort, goUDP.SrcPort)
	}
	if fastPkt.DstPort != uint16(goUDP.DstPort) {
		t.Errorf("UDP DstPort mismatch: fast=%d, gopacket=%d", fastPkt.DstPort, goUDP.DstPort)
	}
	if fastPkt.UDP.SrcPort != uint16(goUDP.SrcPort) {
		t.Errorf("fastPkt.UDP.SrcPort mismatch: fast=%d, gopacket=%d", fastPkt.UDP.SrcPort, goUDP.SrcPort)
	}
	if fastPkt.UDP.DstPort != uint16(goUDP.DstPort) {
		t.Errorf("fastPkt.UDP.DstPort mismatch: fast=%d, gopacket=%d", fastPkt.UDP.DstPort, goUDP.DstPort)
	}

	// Payload Parity
	if !bytes.Equal(fastPkt.Payload, goPayload) {
		t.Errorf("Payload mismatch: fast=%q, gopacket=%q", string(fastPkt.Payload), string(goPayload))
	}
}

func TestFastParser_ExtensionHeader_Fallback(t *testing.T) {
	payload := []byte("Extension header payload")
	rawPkt := buildTestIPv6HopByHopTCP(payload)

	fastPkt, err := ParseEgressPacket(rawPkt)
	if err != nil {
		t.Fatalf("ParseEgressPacket failed: %v", err)
	}
	defer fastPkt.Release()

	// Extension header must transparently trigger fallback to gopacket
	if fastPkt.IsFastPath {
		t.Errorf("Expected IsFastPath=false for IPv6 with Hop-by-Hop extension header")
	}
	if fastPkt.FallbackPacket == nil {
		t.Fatalf("Expected FallbackPacket to be non-nil")
	}

	// Fallback packet should be fully decodeable by gopacket layers
	tcpLayer := fastPkt.FallbackPacket.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		t.Errorf("Expected TCP layer in FallbackPacket")
	}
	tcp := tcpLayer.(*layers.TCP)
	if tcp.SrcPort != 8080 || tcp.DstPort != 9090 {
		t.Errorf("Unexpected ports in fallback TCP: %d -> %d", tcp.SrcPort, tcp.DstPort)
	}
}

func TestFastParser_ShortAndInvalidPackets(t *testing.T) {
	// Too short (<40 bytes)
	_, err := ParseEgressPacket([]byte{0x60, 0x01, 0x02})
	if err != ErrPacketTooShort {
		t.Errorf("Expected ErrPacketTooShort, got: %v", err)
	}

	// IPv4 packet instead of IPv6 (version nibble == 4)
	v4pkt := make([]byte, 40)
	v4pkt[0] = 0x45
	_, err = ParseEgressPacket(v4pkt)
	if err != ErrNotIPv6 {
		t.Errorf("Expected ErrNotIPv6, got: %v", err)
	}
}

func TestFastParser_ZeroAllocations(t *testing.T) {
	payload := []byte("zero allocation benchmarking payload")
	tcpPkt := buildTestIPv6TCP(nil, payload, false, true)
	udpPkt := buildTestIPv6UDP(payload)

	// Test TCP parsing zero allocations
	allocsTCP := testing.AllocsPerRun(1000, func() {
		p, err := ParseEgressPacket(tcpPkt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		p.Release()
	})
	if allocsTCP > 0 {
		t.Errorf("ParseEgressPacket(TCP) allocated %v allocs/op, want 0.0", allocsTCP)
	}

	// Test UDP parsing zero allocations
	allocsUDP := testing.AllocsPerRun(1000, func() {
		p, err := ParseEgressPacket(udpPkt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		p.Release()
	})
	if allocsUDP > 0 {
		t.Errorf("ParseEgressPacket(UDP) allocated %v allocs/op, want 0.0", allocsUDP)
	}

	// Test FlowKey zero allocations
	p, err := ParseEgressPacket(tcpPkt)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Release()

	allocsKey := testing.AllocsPerRun(1000, func() {
		_, ok := p.FlowKey(tcpPkt)
		if !ok {
			t.Fatal("FlowKey extraction failed")
		}
	})
	if allocsKey > 0 {
		t.Errorf("p.FlowKey allocated %v allocs/op, want 0.0", allocsKey)
	}
}
