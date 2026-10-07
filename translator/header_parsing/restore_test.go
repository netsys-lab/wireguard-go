package header_parsing

import (
	"net"
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet/path"
)

func TestTranslateIngressWithFlow_TCP_Restore(t *testing.T) {
	srcIA := mustIA(t, 1, 64496)
	translator := NewTranslator(nil, srcIA, &net.UDPAddr{IP: mustParseIP(t, "127.0.0.9"), Port: 31002}, "", noopLog)
	translator.SetConfiguredIPv4(netip.MustParseAddr("10.44.25.1"))
	// Build an outer SCION packet Y->X (reply) that would have been X->Y on egress
	// Use BuildSCIONPacket to create SCION payload then wrap in outer IPv4/UDP
	// For restoration we need outer packet: RemoteIA,RemoteHost:8000 -> LocalIA,LocalHost:52734
	remoteIA := mustIA(t, 2, 64497)
	localIA := srcIA
	remoteHost := mustParseIP(t, "10.30.34.100")
	localHost := mustParseIP(t, "10.44.25.1")
	// Dummy path
	p := path.Path{}
	flowID := uint32(12345)
	tc := uint8(0)
	// inner TCP that would be B:b->A:a after restore, but outer carries Y->X ports 8000->52734
	innerTCP := &layers.TCP{SrcPort: 8000, DstPort: 52734, Seq: 1, Window: 65535, SYN: true}
	scionBytes, err := BuildSCIONPacket(uint16(remoteIA.ISD()), uint64(remoteIA.AS()), uint16(localIA.ISD()), uint64(localIA.AS()), remoteHost, localHost, flowID, tc, slayers.L4TCP, innerTCP, nil, p, noopLog)
	if err != nil {
		t.Fatalf("BuildSCIONPacket: %v", err)
	}
	// Wrap in outer IPv4/UDP
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	outerIP := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: remoteHost.To4(), DstIP: localHost.To4()}
	udp := &layers.UDP{SrcPort: 8000, DstPort: 52734}
	udp.SetNetworkLayerForChecksum(outerIP)
	if err := gopacket.SerializeLayers(buf, opts, outerIP, udp, gopacket.Payload(scionBytes)); err != nil {
		t.Fatalf("outer serialize: %v", err)
	}
	outer := buf.Bytes()
	// Now restore with flow endpoints A:a fd42::70:52734 and B:b fc00:...:8000
	localAddr := netip.MustParseAddr("fd42:42:42::70")
	remoteAddr := netip.MustParseAddr("fc00:10fb:f000::ffff:a1e:2264") // example mapped
	localPort := uint16(52734)
	remotePort := uint16(8000)
	restored, err := translator.TranslateIngressWithFlow(outer, localAddr, localPort, remoteAddr, remotePort)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	pkt := gopacket.NewPacket(restored, layers.LayerTypeIPv6, gopacket.Default)
	ip6 := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		t.Fatal("no TCP")
	}
	tcpRestored := tcpLayer.(*layers.TCP)
	if !ip6.SrcIP.Equal(net.ParseIP(remoteAddr.String())) {
		t.Fatalf("src IP %s != %s", ip6.SrcIP, remoteAddr.String())
	}
	if !ip6.DstIP.Equal(net.ParseIP(localAddr.String())) {
		t.Fatalf("dst IP %s != %s", ip6.DstIP, localAddr.String())
	}
	if uint16(tcpRestored.SrcPort) != remotePort || uint16(tcpRestored.DstPort) != localPort {
		t.Fatalf("ports %d->%d != %d->%d", tcpRestored.SrcPort, tcpRestored.DstPort, remotePort, localPort)
	}
}

func TestTranslateIngressWithFlow_UDP_Restore(t *testing.T) {
	srcIA := mustIA(t, 1, 64496)
	translator := NewTranslator(nil, srcIA, &net.UDPAddr{IP: mustParseIP(t, "127.0.0.9"), Port: 31002}, "", noopLog)
	translator.SetConfiguredIPv4(netip.MustParseAddr("10.44.25.1"))
	remoteIA := mustIA(t, 2, 64497)
	localIA := srcIA
	remoteHost := mustParseIP(t, "10.30.34.100")
	localHost := mustParseIP(t, "10.44.25.1")
	p := path.Path{}
	innerUDP := &slayers.UDP{SrcPort: 8000, DstPort: 52734}
	scionBytes, err := BuildSCIONPacket(uint16(remoteIA.ISD()), uint64(remoteIA.AS()), uint16(localIA.ISD()), uint64(localIA.AS()), remoteHost, localHost, 0, 0, slayers.L4UDP, innerUDP, []byte("hello"), p, noopLog)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	outerIP := &layers.IPv4{Version: 4, Protocol: layers.IPProtocolUDP, SrcIP: remoteHost.To4(), DstIP: localHost.To4(), TTL: 64}
	udp := &layers.UDP{SrcPort: 8000, DstPort: 52734}
	udp.SetNetworkLayerForChecksum(outerIP)
	gopacket.SerializeLayers(buf, opts, outerIP, udp, gopacket.Payload(scionBytes))
	outer := buf.Bytes()
	localAddr := netip.MustParseAddr("fd42:42:42::70")
	remoteAddr := netip.MustParseAddr("fc00::1")
	restored, err := translator.TranslateIngressWithFlow(outer, localAddr, 52734, remoteAddr, 8000)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	pkt := gopacket.NewPacket(restored, layers.LayerTypeIPv6, gopacket.Default)
	if pkt.Layer(layers.LayerTypeIPv6) == nil {
		t.Fatal("no IPv6")
	}
	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatal("no UDP")
	}
	u := udpLayer.(*layers.UDP)
	if u.SrcPort != 8000 || u.DstPort != 52734 {
		t.Fatalf("ports %d->%d", u.SrcPort, u.DstPort)
	}
}
