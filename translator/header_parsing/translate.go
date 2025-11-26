package header_parsing

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	snetpath "github.com/scionproto/scion/pkg/snet/path"

	"golang.zx2c4.com/wireguard/translator/addr_translation"
)

type Translator struct {
	cache PathCache
	//localISD uint16
	//localASN uint32
}

func NewTranslator(cache PathCache) *Translator {
	return &Translator{cache: cache}
}

const (
	// SCION-mapped IPv6 prefix = fc00::/8
	SCIONPrefixFirstByte = 0xfc
)

type PathCache interface {
	Lookup(srcIA, dstIA addr.IA) ([]snetpath.Path, bool)
}

func (t *Translator) ReadPacket(pkt []byte, isIPv6 bool) ([]byte, error) {
	/*
		Main entry for the Translation atleast for now.
		We can later move the decisions into the send.go
	*/

	return pkt, nil
}

func (t *Translator) getPathFromCache(srcIA, dstIA addr.IA) (snetpath.Path, bool) {
	//Paths retrieval from PathCache
	paths, _ := t.cache.Lookup(srcIA, dstIA)
	//Path Selection Criteria
	//Just select first path for now
	path := selectPath(paths)

	return path, true
}

func selectPath(paths []snetpath.Path) snetpath.Path {
	return paths[0]
}

type GetPathFunc func(srcIA, dstIA addr.IA) (snetpath.Path, bool)

// IPv6 -> SCION
// returns SCION packet bytes and the UDP next-hop to send to if successful
func (t *Translator) TranslateEgress(pktData []byte, hostIP net.IP, hostPort int, getPath GetPathFunc) ([]byte, *net.UDPAddr, error) {
	// Parse IPv6 packet
	packet := gopacket.NewPacket(pktData, layers.LayerTypeIPv6, gopacket.Default)
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if packet.Layer(layers.LayerTypeIPv6) == nil {
		return nil, nil, errors.New("not an IPv6 packet")
	}
	ip6 := ip6Layer.(*layers.IPv6)

	if !isSCIONMapped(ip6.DstIP) {
		return nil, nil, errors.New("dst not in SCION-mapped network")
	}

	isd, asn, _, _, host, hostIsIPv4, err := UnmapIPv6(ip6.DstIP, 8) // subnetBits = 8
	if err != nil {
		return nil, nil, fmt.Errorf("unmap IPv6 failed: %w", err)
	}

	srcisd, srcasn, _, _, _, _, err := UnmapIPv6(ip6.SrcIP, 8)
	if err != nil {
		return nil, nil, fmt.Errorf("src unmap IPv6 failed: %w", err)
	}

	//pathBytes, nextHop, ok := pathCache.Lookup(dstIA)
	//if !ok || len(pathBytes) == 0 {
	// return nil, nil, errors.New("no path available for dst IA")
	//fmt.Println("PathCache miss for dst IA, falling back to direct host+port")

	dstIA := addr.IA(addr.MustIAFrom(addr.ISD(isd), addr.AS(asn)))
	srcIA := addr.IA(addr.MustIAFrom(addr.ISD(srcisd), addr.AS(srcasn)))

	//Using the Callback functio
	var (
		selectedPath snetpath.Path
		ok           bool
	)
	if getPath != nil {
		selectedPath, ok = getPath(srcIA, dstIA)
	} else {
		selectedPath, ok = t.getPathFromCache(srcIA, dstIA)
	}
	if !ok {
		return nil, nil, errors.New("no path available for dst IA")
	}
	//Return a snet.path.Scion and nexthopfield
	nextHop := selectedPath.UnderlayNextHop()

	// extract L4 layer and ensure supported protocols (UDP, TCP)
	var l4Payload []byte
	nextHeader := ip6.NextHeader
	var l4nextHeader slayers.L4ProtocolType
	switch nextHeader {
	case layers.IPProtocolUDP:
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return nil, nil, errors.New("udp layer missing")
		}
		l4nextHeader = slayers.L4UDP
		udp := udpLayer.(*layers.UDP)
		l4Payload = udp.Contents
		l4Payload = append(l4Payload, udp.Payload...)
	case layers.IPProtocolTCP:
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			return nil, nil, errors.New("tcp layer missing")
		}
		l4nextHeader = slayers.L4TCP
		tcp := tcpLayer.(*layers.TCP)
		l4Payload = tcp.Contents
		l4Payload = append(l4Payload, tcp.Payload...)
	case layers.IPProtocolICMPv6: // 58
		// for simplicity no ICMPv6 -> SCMP translation here yet
		l4nextHeader = slayers.L4SCMP
		return nil, nil, errors.New("ICMPv6 -> SCMP translation not (yet) implemented")
	default:
		return nil, nil, fmt.Errorf("unsupported upper-layer protocol: %d", nextHeader)
	}

	var dstHost net.IP
	if hostIsIPv4 {
		dstHost = host.To4()
	} else {
		dstHost = host // full IPv6 host inside SCION mapping
	}

	// If pathBytes encode an "empty path", the PathCache implementation could
	// return nextHop==nil — in that case we assume direct host+port using hostPort.
	// Here we prefer nextHop returned by PathCache if non-nil; otherwise fallback to host+hostPort.
	if nextHop == nil {
		// fallback direct to mapped host and given port
		if dstHost.To4() != nil {
			nextHop = &net.UDPAddr{IP: dstHost, Port: hostPort}
		} else {
			nextHop = &net.UDPAddr{IP: dstHost, Port: hostPort, Zone: ""}
		}
	}

	//TODO: What does this do? Needs implementation
	//localISD, localASN := pathcache.LocalIA()
	localISD := srcisd
	localASN := srcasn

	scionBytes, err := BuildSCIONPacket(localISD, localASN, uint16(isd), asn, hostIP, dstHost, l4nextHeader, selectedPath, l4Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("build scion packet failed: %w", err)
	}

	return scionBytes, nextHop, nil
}

// SCION -> IPv6
func (t *Translator) TranslateIngress(pktData []byte, tunIP net.IP) ([]byte, error) {
	var scion slayers.SCION
	//var scmp slayers.SCMP
	var udp layers.UDP
	var tcp layers.TCP

	// decode only above protocols
	//parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION, &scion, &udp, &tcp, &scmp)
	parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION, &scion)
	decoded := []gopacket.LayerType{}

	if err := parser.DecodeLayers(pktData, &decoded); err != nil {
		return nil, fmt.Errorf("failed to parse SCION: %w", err)
	}

	// ---- dst ----
	var dst net.IP
	isd := int(scion.DstIA.ISD())
	asn := addr_translation.ASN{Value: uint64(scion.DstIA.AS())}
	iface := net.IP(scion.RawDstAddr)
	switch scion.DstAddrType {
	case slayers.T4Ip:
		var err error
		dst, err = addr_translation.ScionToIP(isd, asn, 0, 0, iface, 8)
		if err != nil {
			return nil, fmt.Errorf("ScionToIP failed: %w", err)
		}
	case slayers.T16Ip:
		dst = net.IP(scion.RawDstAddr)
	default:
		return nil, errors.New("unsupported destination host type")
	}

	// must match tunnel endpoint
	//if !dst.Equal(tunIP) {
	//return nil, errors.New("packet not for this tunnel endpoint")
	//}

	// ---- src ----
	var src net.IP
	switch scion.SrcAddrType {
	case slayers.T4Ip:
		var err error
		src, err = addr_translation.ScionToIP(isd, asn, 0, 0, iface, 8)
		if err != nil {
			return nil, fmt.Errorf("ScionToIP failed: %w", err)
		}
	case slayers.T16Ip:
		src = net.IP(scion.RawSrcAddr)
		if !isSCIONMapped(src) {
			return nil, errors.New("src not in SCION-mapped network")
		}
	default:
		return nil, errors.New("unsupported source host type")
	}

	// ---- L4 payload ----
	var l4Layer gopacket.SerializableLayer

	for _, layerType := range decoded {
		switch layerType {
		case layers.LayerTypeUDP:
			udp.SetNetworkLayerForChecksum(&scion)
			l4Layer = &udp
		case layers.LayerTypeTCP:
			tcp.SetNetworkLayerForChecksum(&scion)
			l4Layer = &tcp
		case slayers.LayerTypeSCMP: //TODO: implement SCMP -> ICMPv6 translation
			l4Layer = nil
			// icmp, err := scmpToICMP(&scmp)
			// if err != nil {
			// 	return nil, errors.New("failed to translate SCMP to ICMP")
			// }
			// l4Layer = icmp
		case slayers.LayerTypeSCIONUDP:
			l4Layer = nil
		case slayers.LayerTypeSCION:
			l4Layer = &scion
		}
	}

	if l4Layer == nil {
		return nil, errors.New("unsupported L4 type")
	}

	// ---- Build IPv6 ----
	ip6 := &layers.IPv6{
		Version: 6,
		SrcIP:   src,
		DstIP:   dst,
		//TODO: set correct nextheader field
		NextHeader: layers.IPProtocol(l4Layer.LayerType().LayerTypes()[0]),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, ip6, l4Layer); err != nil {
		return nil, fmt.Errorf("failed to serialize IPv6: %w", err)
	}

	return buf.Bytes(), nil
}

// TODO: implement SCMP -> ICMPv6 translation
func scmpToICMP(sCMP *slayers.SCMP) ([]byte, error) {
	icmp := &layers.ICMPv6Echo{}
	// icmp.SetNetworkLayerForChecksum(&layers.IPv6{}) // dummy IPv6 for checksum calc
	return icmp.LayerPayload(), nil
}

// isSCIONMapped returns true if ip is in fc00::/8
func isSCIONMapped(ip net.IP) bool {
	ip = ip.To16()
	if ip == nil {
		return false // if invalid/non-ipv6 ip addr
	}
	return ip[0] == SCIONPrefixFirstByte // fc00::/8
}

func UnmapIPv6(ip net.IP, subnetBits uint) (uint16, uint32, uint32, uint32, net.IP, bool, error) {
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

	asn := uint32((hi >> 24) & 0x000fffff)

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

func BuildSCIONPacket(localISD uint16, localASN uint32, dstISD uint16, dstASN uint32, srcHost net.IP, dstHost net.IP, nextHeader slayers.L4ProtocolType, path snetpath.Path, l4Payload []byte) ([]byte, error) {
	//ToDO: dstISD and localISD should both be 1 where do you get dstISD 0? DstASN is also 0, we need to get dstASN from somewhere too.
	ia, err := addr.IAFrom(addr.ISD(dstISD), addr.AS(dstASN))
	if err != nil {
		return nil, fmt.Errorf("invalid dst IA: %w", err)
	}

	pkt := &slayers.SCION{
		Version:      slayers.SCIONVersion, //0
		TrafficClass: 0,
		FlowID:       0,
		NextHdr:      nextHeader,
		PathType:     0,
		DstAddrType:  0,
		SrcAddrType:  0,

		//add header fields
		SrcIA:      addr.MustIAFrom(addr.ISD(localISD), addr.AS(localASN)),
		DstIA:      ia,
		RawSrcAddr: srcHost,
		RawDstAddr: dstHost,
		//Path will be set with teh Dataplane later
	}
	pkt.Payload = l4Payload

	//This Sets the Path once the scion paket is build
	if err := path.DataplanePath.SetPath(pkt); err != nil {
		return nil, fmt.Errorf("set dataplane path: %w", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, pkt); err != nil {
		return nil, fmt.Errorf("failed to serialize SCION packet: %w", err)
	}
	return buf.Bytes(), nil

}
