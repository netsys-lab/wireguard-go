package device

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"golang.zx2c4.com/wireguard/flow"
	"golang.zx2c4.com/wireguard/translator/header_parsing"
)

// buildShowpathsPacket mirrors header_parsing test helper for Device tests.
func buildShowpathsPacket() []byte {
	srcIA, _ := addr.ParseIA("1-64512")
	dstIA, _ := addr.ParseIA("3-64534")
	scn := slayers.SCION{
		Version:      0,
		TrafficClass: 0,
		FlowID:       0x1234,
		NextHdr:      slayers.L4SCMP,
		PathType:     empty.PathType,
		DstIA:        dstIA,
		SrcIA:        srcIA,
	}
	_ = scn.SetSrcAddr(addr.HostIP(netip.MustParseAddr("10.0.0.2")))
	_ = scn.SetDstAddr(addr.HostSVC(addr.SvcNone))
	scmp := slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
	}
	pld := make([]byte, 4)
	binary.BigEndian.PutUint16(pld[0:2], 32767)
	binary.BigEndian.PutUint16(pld[2:4], 1)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	scn.Path = empty.Path{}
	if err := gopacket.SerializeLayers(buf, opts, &scn, &scmp, gopacket.Payload(pld)); err != nil {
		panic(err)
	}
	scionBytes := buf.Bytes()
	outerBuf := gopacket.NewSerializeBuffer()
	ipv4 := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("10.0.0.2").To4(),
		DstIP:    net.ParseIP("10.0.0.4").To4(),
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(32767),
		DstPort: layers.UDPPort(31004),
	}
	if err := udp.SetNetworkLayerForChecksum(&ipv4); err != nil {
		panic(err)
	}
	opts2 := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(outerBuf, opts2, &ipv4, &udp, gopacket.Payload(scionBytes)); err != nil {
		panic(err)
	}
	return outerBuf.Bytes()
}

func TestNativeSCMP_EgressRegistration_SVC(t *testing.T) {
	pkt := buildShowpathsPacket()
	// Step 1: ClassifyEgress must be Native
	if got := header_parsing.ClassifyEgress(pkt); got != header_parsing.ClassNativeSCION {
		t.Fatalf("ClassifyEgress expected NativeSCION, got %d", got)
	}
	// Step 2: ExtractSCMPInfo must succeed with SVC dst
	info, err := header_parsing.ExtractSCMPInfo(pkt)
	if err != nil {
		t.Fatalf("ExtractSCMPInfo failed: %v", err)
	}
	if info.IsError {
		t.Fatalf("expected informational, got IsError")
	}
	if info.Family != header_parsing.SCMPFamilyTraceroute {
		t.Fatalf("family expected Traceroute, got %v", info.Family)
	}
	if info.Identifier != 32767 || info.Sequence != 1 {
		t.Fatalf("id/seq mismatch got %d/%d", info.Identifier, info.Sequence)
	}
	// Step 3: ObserveTx with native SCION
	d := &Device{flowManager: flow.NewManager()}
	md := flow.PacketMetadata{
		IPVersion:    4,
		Protocol:     flow.ProtocolSCMP,
		Source:       flow.Endpoint{Addr: info.SrcHost, Port: info.Identifier},
		Destination:  flow.Endpoint{Addr: info.DstHost, Port: info.Identifier},
		SrcIA:        info.SrcIA.String(),
		DstIA:        info.DstIA.String(),
		TrafficClass: flow.ClassNativeSCION,
	}
	snap, created := d.flowManager.ObserveTx(md, len(pkt), "scion")
	if !created {
		t.Fatalf("expected new flow created")
	}
	if snap.TrafficClass != flow.ClassNativeSCION {
		t.Fatalf("expected TrafficClass Native, got %v", snap.TrafficClass)
	}
	if snap.EgressKind != flow.EgressSCION {
		t.Fatalf("expected EgressKind scion, got %v", snap.EgressKind)
	}
	if snap.Protocol != flow.ProtocolSCMP {
		t.Fatalf("expected Protocol SCMP, got %v", snap.Protocol)
	}
	// Step 4: rememberSCMPInfo
	d.rememberSCMPInfo(snap.ID, info.Family, info.SrcIA, info.SrcHost, info.Identifier, info.Sequence)
	// Lookup via reply perspective (local host same)
	snap2, res := d.lookupSCMPInfo(info.Family, info.SrcIA, info.SrcHost, 32767, 1)
	if res != SCIONLookupHit {
		t.Fatalf("expected HIT for SCMPInfo, got %v", res)
	}
	if snap2.ID != snap.ID {
		t.Fatalf("lookup returned wrong flow %d vs %d", snap2.ID, snap.ID)
	}
	// SCMPInfoKey fields check
	key := SCMPInfoKey{Family: header_parsing.SCMPFamilyTraceroute, LocalIA: info.SrcIA, LocalHost: info.SrcHost, Identifier: 32767, Sequence: 1}
	if snap.ID == 0 {
		t.Fatalf("flow ID zero")
	}
	_ = key
}
