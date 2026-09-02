package header_parsing

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
)

// SCIONTuple is the authoritative wire identity of a SCION TCP/UDP flow.
type SCIONTuple struct {
	Protocol uint8
	SrcIA    addr.IA
	DstIA    addr.IA
	SrcHost  netip.Addr
	DstHost  netip.Addr
	SrcPort  uint16
	DstPort  uint16
}

// ExtractSCIONTuple parses outer IPv4/UDP/SCION or IPv6/UDP/SCION and returns the SCION L4 identity.
// It mirrors TranslateIngress outer parsing but only extracts the tuple.
func ExtractSCIONTuple(packet []byte) (SCIONTuple, error) {
	if len(packet) < 20 {
		return SCIONTuple{}, fmt.Errorf("packet too short")
	}
	version := packet[0] >> 4
	var scionPayload []byte
	var outerDstPort uint16
	_ = outerDstPort
	switch version {
	case 4:
		pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
		ip4Layer := pkt.Layer(layers.LayerTypeIPv4)
		if ip4Layer == nil {
			return SCIONTuple{}, fmt.Errorf("no IPv4 layer")
		}
		ip4 := ip4Layer.(*layers.IPv4)
		if ip4.Protocol != layers.IPProtocolUDP {
			return SCIONTuple{}, fmt.Errorf("outer IPv4 not UDP")
		}
		udpLayer := pkt.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return SCIONTuple{}, fmt.Errorf("no UDP layer")
		}
		udpOuter := udpLayer.(*layers.UDP)
		scionPayload = udpOuter.Payload
	case 6:
		pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv6, gopacket.Default)
		ip6Layer := pkt.Layer(layers.LayerTypeIPv6)
		if ip6Layer == nil {
			return SCIONTuple{}, fmt.Errorf("no IPv6 layer")
		}
		ip6 := ip6Layer.(*layers.IPv6)
		if ip6.NextHeader != layers.IPProtocolUDP {
			return SCIONTuple{}, fmt.Errorf("outer IPv6 not UDP")
		}
		udpLayer := pkt.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return SCIONTuple{}, fmt.Errorf("no UDP layer")
		}
		udpOuter := udpLayer.(*layers.UDP)
		scionPayload = udpOuter.Payload
	default:
		return SCIONTuple{}, fmt.Errorf("unknown IP version")
	}
	if len(scionPayload) == 0 {
		return SCIONTuple{}, fmt.Errorf("no SCION payload")
	}
	var scn slayers.SCION
	var udp slayers.UDP
	var tcp layers.TCP
	var scmp slayers.SCMP
	var pld gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(
		slayers.LayerTypeSCION,
		&scn,
		&udp,
		&tcp,
		&scmp,
		&pld,
	)
	parser.IgnoreUnsupported = true
	var decoded []gopacket.LayerType
	if err := parser.DecodeLayers(scionPayload, &decoded); err != nil {
		return SCIONTuple{}, fmt.Errorf("SCION decode failed: %w", err)
	}
	var proto uint8
	var srcPort, dstPort uint16
	for _, lt := range decoded {
		switch lt {
		case slayers.LayerTypeSCIONUDP:
			proto = 17
			srcPort = udp.SrcPort
			dstPort = udp.DstPort
		case layers.LayerTypeTCP:
			proto = 6
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
		case slayers.LayerTypeSCMP:
			// SCMP not handled for flow index; return error so caller can skip
			return SCIONTuple{}, fmt.Errorf("SCMP not for TCP/UDP index")
		}
	}
	if proto == 0 && scn.NextHdr == slayers.L4TCP {
		raw := []byte(pld)
		if err := tcp.DecodeFromBytes(raw, gopacket.NilDecodeFeedback); err == nil {
			proto = 6
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
		}
	}
	if proto != 6 && proto != 17 {
		return SCIONTuple{}, fmt.Errorf("unsupported L4 %v", scn.NextHdr)
	}
	srcHost, err := rawToNetip(scn.SrcAddrType, scn.RawSrcAddr)
	if err != nil {
		return SCIONTuple{}, fmt.Errorf("src host: %w", err)
	}
	dstHost, err := rawToNetip(scn.DstAddrType, scn.RawDstAddr)
	if err != nil {
		return SCIONTuple{}, fmt.Errorf("dst host: %w", err)
	}
	return SCIONTuple{
		Protocol: proto,
		SrcIA:    scn.SrcIA,
		DstIA:    scn.DstIA,
		SrcHost:  srcHost,
		DstHost:  dstHost,
		SrcPort:  srcPort,
		DstPort:  dstPort,
	}, nil
}

// SCMPInfoFamily distinguishes Echo vs Traceroute
type SCMPInfoFamily uint8

const (
	SCMPFamilyEcho       SCMPInfoFamily = 0
	SCMPFamilyTraceroute SCMPInfoFamily = 1
)

type SCMPInfo struct {
	Family     SCMPInfoFamily
	Identifier uint16
	Sequence   uint16
	SrcIA      addr.IA
	DstIA      addr.IA
	SrcHost    netip.Addr
	DstHost    netip.Addr
	Type       slayers.SCMPType
	IsError    bool
	// For errors, QuotedTuple is the offending packet's tuple (TCP/UDP SCION)
	QuotedTuple *SCIONTuple
}

// ExtractSCMPInfo parses outer SCMP packet and returns SCMP informational identity.
// For informational Echo/Traceroute, it extracts Identifier/Sequence and family.
// For SCMP errors, it extracts quoted SCION tuple if present.
func ExtractSCMPInfo(packet []byte) (SCMPInfo, error) {
	if len(packet) < 20 {
		return SCMPInfo{}, fmt.Errorf("packet too short")
	}
	version := packet[0] >> 4
	var scionPayload []byte
	switch version {
	case 4:
		pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
		udpLayer := pkt.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return SCMPInfo{}, fmt.Errorf("no UDP")
		}
		udp := udpLayer.(*layers.UDP)
		scionPayload = udp.Payload
	case 6:
		pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv6, gopacket.Default)
		udpLayer := pkt.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return SCMPInfo{}, fmt.Errorf("no UDP")
		}
		udp := udpLayer.(*layers.UDP)
		scionPayload = udp.Payload
	default:
		return SCMPInfo{}, fmt.Errorf("unknown IP version")
	}
	if len(scionPayload) == 0 {
		return SCMPInfo{}, fmt.Errorf("no SCION payload")
	}
	var scn slayers.SCION
	var scmp slayers.SCMP
	var pld gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION, &scn, &scmp, &pld)
	parser.IgnoreUnsupported = true
	var decoded []gopacket.LayerType
	if err := parser.DecodeLayers(scionPayload, &decoded); err != nil {
		return SCMPInfo{}, fmt.Errorf("SCION decode: %w", err)
	}
	foundSCMP := false
	for _, lt := range decoded {
		if lt == slayers.LayerTypeSCMP {
			foundSCMP = true
			break
		}
	}
	if !foundSCMP {
		return SCMPInfo{}, fmt.Errorf("not SCMP")
	}
	scmpType := scmp.TypeCode.Type()
	isError := scmpType != slayers.SCMPTypeEchoRequest && scmpType != slayers.SCMPTypeEchoReply && scmpType != slayers.SCMPTypeTracerouteRequest && scmpType != slayers.SCMPTypeTracerouteReply
	var family SCMPInfoFamily
	switch scmpType {
	case slayers.SCMPTypeEchoRequest, slayers.SCMPTypeEchoReply:
		family = SCMPFamilyEcho
	case slayers.SCMPTypeTracerouteRequest, slayers.SCMPTypeTracerouteReply:
		family = SCMPFamilyTraceroute
	default:
		if isError {
			// For errors, try to extract quoted tuple from payload
			quoted := []byte(pld)
			if len(quoted) == 0 {
				quoted = scmp.LayerPayload()
			}
			var qt *SCIONTuple
			if len(quoted) > 0 {
				if tup, err := parseQuotedSCION(quoted); err == nil {
					qt = &tup
				} else if tup2, err2 := parseQuotedSCION(scmp.LayerPayload()); err2 == nil {
					qt = &tup2
				}
			}
			srcHost, _ := rawToNetip(scn.SrcAddrType, scn.RawSrcAddr)
			dstHost, _ := rawToNetip(scn.DstAddrType, scn.RawDstAddr)
			// For errors, identifier/sequence not used for key, set 0
			return SCMPInfo{Family: SCMPFamilyEcho, Identifier: 0, Sequence: 0, SrcIA: scn.SrcIA, DstIA: scn.DstIA, SrcHost: srcHost, DstHost: dstHost, Type: scmpType, IsError: true, QuotedTuple: qt}, nil
		}
		return SCMPInfo{}, fmt.Errorf("unsupported SCMP type %v", scmpType)
	}
	// Informational: identifier/sequence from echo payload (4 bytes: id, seq)
	pldBytes := []byte(pld)
	if len(pldBytes) < 4 {
		// Try scmp LayerPayload as well
		pldBytes = scmp.LayerPayload()
	}
	var identifier, sequence uint16
	if len(pldBytes) >= 4 {
		identifier = binary.BigEndian.Uint16(pldBytes[0:2])
		sequence = binary.BigEndian.Uint16(pldBytes[2:4])
	} else if len(scmp.LayerPayload()) >= 4 {
		b := scmp.LayerPayload()
		identifier = binary.BigEndian.Uint16(b[0:2])
		sequence = binary.BigEndian.Uint16(b[2:4])
	}
	srcHost, err := rawToNetip(scn.SrcAddrType, scn.RawSrcAddr)
	if err != nil {
		return SCMPInfo{}, err
	}
	dstHost, err := rawToNetip(scn.DstAddrType, scn.RawDstAddr)
	if err != nil {
		return SCMPInfo{}, err
	}
	return SCMPInfo{
		Family:     family,
		Identifier: identifier,
		Sequence:   sequence,
		SrcIA:      scn.SrcIA,
		DstIA:      scn.DstIA,
		SrcHost:    srcHost,
		DstHost:    dstHost,
		Type:       scmpType,
		IsError:    false,
	}, nil
}

func parseQuotedSCION(quoted []byte) (SCIONTuple, error) {
	if len(quoted) < 1 {
		return SCIONTuple{}, fmt.Errorf("quoted too short")
	}
	// Quoted is SCION packet bytes (SCION header + L4)
	var scn slayers.SCION
	var udp slayers.UDP
	var tcp layers.TCP
	var pld gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION, &scn, &udp, &tcp, &pld)
	parser.IgnoreUnsupported = true
	var decoded []gopacket.LayerType
	if err := parser.DecodeLayers(quoted, &decoded); err != nil {
		return SCIONTuple{}, err
	}
	var proto uint8
	var srcPort, dstPort uint16
	for _, lt := range decoded {
		switch lt {
		case slayers.LayerTypeSCIONUDP:
			proto = 17
			srcPort = udp.SrcPort
			dstPort = udp.DstPort
		case layers.LayerTypeTCP:
			proto = 6
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
		}
	}
	if proto == 0 && scn.NextHdr == slayers.L4TCP {
		raw := []byte(pld)
		if err := tcp.DecodeFromBytes(raw, gopacket.NilDecodeFeedback); err == nil {
			proto = 6
			srcPort = uint16(tcp.SrcPort)
			dstPort = uint16(tcp.DstPort)
		}
	}
	if proto != 6 && proto != 17 {
		return SCIONTuple{}, fmt.Errorf("quoted not TCP/UDP")
	}
	srcHost, err := rawToNetip(scn.SrcAddrType, scn.RawSrcAddr)
	if err != nil {
		return SCIONTuple{}, err
	}
	dstHost, err := rawToNetip(scn.DstAddrType, scn.RawDstAddr)
	if err != nil {
		return SCIONTuple{}, err
	}
	return SCIONTuple{Protocol: proto, SrcIA: scn.SrcIA, DstIA: scn.DstIA, SrcHost: srcHost, DstHost: dstHost, SrcPort: srcPort, DstPort: dstPort}, nil
}

func rawToNetip(addrType slayers.AddrType, raw []byte) (netip.Addr, error) {
	ip := net.IP(raw)
	switch addrType {
	case slayers.T4Ip:
		if ip4 := ip.To4(); ip4 != nil {
			return netip.AddrFrom4([4]byte(ip4)), nil
		}
		return netip.Addr{}, fmt.Errorf("invalid T4Ip %v", raw)
	case slayers.T16Ip:
		if ip16 := ip.To16(); ip16 != nil {
			// If already 16, use as is
			var b [16]byte
			copy(b[:], ip16)
			return netip.AddrFrom16(b), nil
		}
		return netip.Addr{}, fmt.Errorf("invalid T16Ip %v", raw)
	default:
		return netip.Addr{}, fmt.Errorf("unsupported addr type %v", addrType)
	}
}

// Helper for outer IPv4 IHL parsing for classifier already but reused.

func ipToNetipHost(ip net.IP) netip.Addr {
	if ip4 := ip.To4(); ip4 != nil {
		var b [4]byte
		copy(b[:], ip4)
		return netip.AddrFrom4(b)
	}
	if ip16 := ip.To16(); ip16 != nil {
		var b [16]byte
		copy(b[:], ip16)
		return netip.AddrFrom16(b)
	}
	return netip.Addr{}
}

func netipToIP(a netip.Addr) net.IP {
	if !a.IsValid() {
		return nil
	}
	if a.Is4() {
		b := a.As4()
		return net.IPv4(b[0], b[1], b[2], b[3])
	}
	b := a.As16()
	return net.IP(b[:])
}

// isSCIONCommonHeader checks version nibble 0 without full decode.
func isSCIONCommonHeader(b []byte) bool {
	if len(b) < 1 {
		return false
	}
	return b[0]>>4 == 0
}

var _ = binary.BigEndian
var _ = isSCIONCommonHeader
