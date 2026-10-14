package header_parsing

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
)

// buildShowpathsTraceroutePacket builds the real showpaths packet:
// Outer IPv4 10.0.0.2:32767 -> 10.0.0.4:31004
// SCION Src 1-64512 [10.0.0.2] Dst 3-64534 [SvcNone 0xffff] NextHdr SCMP
// SCMP TracerouteRequest id=32767 seq=1
func buildShowpathsTraceroutePacket() []byte {
	srcIA, _ := addr.ParseIA("1-64512")
	dstIA, _ := addr.ParseIA("3-64534")
	// SCION layer
	scn := slayers.SCION{
		Version:      0,
		TrafficClass: 0,
		FlowID:       0x1234,
		NextHdr:      slayers.L4SCMP,
		PathType:     empty.PathType,
		DstIA:        dstIA,
		SrcIA:        srcIA,
	}
	// Set addresses: Src T4Ip 10.0.0.2, Dst T4Svc SvcNone
	_ = scn.SetSrcAddr(addr.HostIP(netip.MustParseAddr("10.0.0.2")))
	_ = scn.SetDstAddr(addr.HostSVC(addr.SvcNone))
	// SCMP TracerouteRequest
	scmp := slayers.SCMP{
		TypeCode: slayers.CreateSCMPTypeCode(slayers.SCMPTypeTracerouteRequest, 0),
		Checksum: 0,
	}
	// Payload for informational SCMP: 4 bytes id+seq
	pld := make([]byte, 4)
	binary.BigEndian.PutUint16(pld[0:2], 32767)
	binary.BigEndian.PutUint16(pld[2:4], 1)
	scionPayload := gopacket.NewPacket(nil, nil, gopacket.Default)
	// Serialize SCION+SCMP+payload into raw SCION bytes
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	opts2 := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = opts2
	// Need path empty - set path accordingly
	scn.Path = empty.Path{}
	if err := gopacket.SerializeLayers(buf, opts, &scn, &scmp, gopacket.Payload(pld)); err != nil {
		panic(err)
	}
	_ = scionPayload
	scionBytes := buf.Bytes()
	outerBuf2 := gopacket.NewSerializeBuffer()
	opts = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ipv4ForOuter := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("10.0.0.2").To4(),
		DstIP:    net.ParseIP("10.0.0.4").To4(),
	}
	udpForOuter := layers.UDP{
		SrcPort: layers.UDPPort(32767),
		DstPort: layers.UDPPort(31004),
	}
	if err := udpForOuter.SetNetworkLayerForChecksum(&ipv4ForOuter); err != nil {
		panic(err)
	}
	if err := gopacket.SerializeLayers(outerBuf2, opts, &ipv4ForOuter, &udpForOuter, gopacket.Payload(scionBytes)); err != nil {
		panic(err)
	}
	return outerBuf2.Bytes()
}

func TestClassifyEgress_ShowpathsSVC(t *testing.T) {
	pkt := buildShowpathsTraceroutePacket()
	if got := ClassifyEgress(pkt); got != ClassNativeSCION {
		t.Fatalf("ClassifyEgress for showpaths SVC packet expected Native (%d), got %d", ClassNativeSCION, got)
	}
	// ordinary UDP same ports but non-SCION must be Plain
	plain := make([]byte, 20+8+4)
	plain[0] = (4 << 4) | 5
	plain[9] = 17
	binary.BigEndian.PutUint16(plain[2:4], uint16(len(plain)))
	binary.BigEndian.PutUint16(plain[20:22], 32767)
	binary.BigEndian.PutUint16(plain[22:24], 31004)
	copy(plain[28:32], []byte("test"))
	if got := ClassifyEgress(plain); got != ClassPlainIP {
		t.Fatalf("ordinary UDP with 31004 but non-SCION should be Plain, got %d", got)
	}
}

func TestExtractSCMPInfo_ShowpathsSVC(t *testing.T) {
	pkt := buildShowpathsTraceroutePacket()
	info, err := ExtractSCMPInfo(pkt)
	if err != nil {
		t.Fatalf("ExtractSCMPInfo failed for SVC packet: %v", err)
	}
	if info.IsError {
		t.Fatalf("expected informational, got IsError true")
	}
	if info.Family != SCMPFamilyTraceroute {
		t.Fatalf("expected Traceroute family, got %v", info.Family)
	}
	if info.Identifier != 32767 || info.Sequence != 1 {
		t.Fatalf("expected id 32767 seq 1, got id=%d seq=%d", info.Identifier, info.Sequence)
	}
	expIA, _ := addr.ParseIA("1-64512")
	if info.SrcIA != expIA {
		t.Fatalf("expected SrcIA 1-64512, got %s", info.SrcIA)
	}
	expHost := netip.MustParseAddr("10.0.0.2")
	if info.SrcHost != expHost {
		t.Fatalf("expected LocalHost 10.0.0.2, got %s", info.SrcHost)
	}
	// DstHost should be invalid (SVC) but not cause error
	if info.DstHost.IsValid() {
		t.Fatalf("expected DstHost invalid for SVC, got %s", info.DstHost)
	}
	// DstIA should be 3-64534 even with SVC
	expDstIA, _ := addr.ParseIA("3-64534")
	if info.DstIA != expDstIA {
		t.Fatalf("expected DstIA 3-64534, got %s", info.DstIA)
	}
}

func TestRawToNetip_SVC(t *testing.T) {
	// T4Svc should return invalid without error
	host, err := rawToNetip(slayers.T4Svc, []byte{0xff, 0xff})
	if err != nil {
		t.Fatalf("rawToNetip T4Svc should not error, got %v", err)
	}
	if host.IsValid() {
		t.Fatalf("T4Svc should be invalid Addr, got %v", host)
	}
}
