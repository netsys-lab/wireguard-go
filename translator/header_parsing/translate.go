package header_parsing

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
	"github.com/scionproto/scion/pkg/snet"

	"github.com/scionproto/scion/pkg/snet/path"
	"golang.zx2c4.com/wireguard/translator/addr_translation"
	pathpool "golang.zx2c4.com/wireguard/translator/pathpool"
)

//--------------- Helper

func packetSummary(pkt []byte) string {
	if len(pkt) == 0 {
		return "len=0"
	}
	firstNibble := pkt[0] >> 4
	return fmt.Sprintf("len=%d firstNibble=%d firstByte=0x%02x", len(pkt), firstNibble, pkt[0])
}

func ipString(ip net.IP) string {
	if ip == nil {
		return "<nil>"
	}
	return ip.String()
}

func udpAddrString(a *net.UDPAddr) string {
	if a == nil {
		return "<nil>"
	}
	return a.String()
}

func IPv4OfInterface(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q not found: %w", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("get addresses for interface %q: %w", ifaceName, err)
	}

	for _, addr := range addrs {
		var ip net.IP

		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}

		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}

	return nil, fmt.Errorf("no IPv4 address found on interface %q", ifaceName)
}

func IPv6OfInterface(ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q not found: %w", ifaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("get addresses for interface %q: %w", ifaceName, err)
	}

	for _, addr := range addrs {
		var ip net.IP

		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}

		if ip.To4() != nil {
			continue
		}

		ip16 := ip.To16()
		if ip16 == nil {
			continue
		}

		if ip.IsLinkLocalUnicast() {
			continue
		}

		return ip16, nil
	}

	return nil, fmt.Errorf("no non-link-local IPv6 address found on interface %q", ifaceName)
}

func (t *Translator) WGSrcIPv4() (net.IP, error) {
	t.wgSrcIPMu.RLock()
	if t.wgSrcIP != nil && t.wgSrcIP.To4() != nil {
		ip := append(net.IP(nil), t.wgSrcIP...)
		t.wgSrcIPMu.RUnlock()

		log.Printf("[WG-ADDR] using cached WG IPv4 iface=%s ip=%s", t.ifaceName, ip)
		return ip, nil
	}
	t.wgSrcIPMu.RUnlock()

	t.wgSrcIPMu.Lock()
	defer t.wgSrcIPMu.Unlock()

	// Double-check, falls eine andere Goroutine die IP inzwischen gesetzt hat.
	if t.wgSrcIP != nil && t.wgSrcIP.To4() != nil {
		ip := append(net.IP(nil), t.wgSrcIP...)
		log.Printf("[WG-ADDR] using cached WG IPv4 after lock iface=%s ip=%s", t.ifaceName, ip)
		return ip, nil
	}

	if t.ifaceName == "" {
		return nil, fmt.Errorf("translator ifaceName is empty")
	}

	ip, err := IPv4OfInterface(t.ifaceName)
	if err != nil {
		log.Printf("[WG-ADDR] lazy WG IPv4 lookup failed iface=%s err=%v", t.ifaceName, err)
		return nil, err
	}

	t.wgSrcIP = append(net.IP(nil), ip...)

	log.Printf("[WG-ADDR] lazy WG IPv4 lookup success iface=%s ip=%s", t.ifaceName, ip)

	return append(net.IP(nil), ip...), nil
}

func (t *Translator) IAPairForMappedDst(dstIP net.IP) (addr.IA, addr.IA, error) {
	log.Printf("[IA-MAP] enter dstIP=%s localIA=%s", ipString(dstIP), t.localIA)

	if !IsSCIONMapped(dstIP) {
		log.Printf("[IA-MAP] not SCION-mapped dstIP=%s", ipString(dstIP))
		return 0, 0, fmt.Errorf("dst IP is not SCION-mapped: %s", dstIP)
	}

	isd, asn, localPrefix, subnet, host, hostIsIPv4, err := UnmapIPv6(dstIP, 8)
	if err != nil {
		log.Printf("[IA-MAP] UnmapIPv6 failed dstIP=%s err=%v", ipString(dstIP), err)
		return 0, 0, fmt.Errorf("unmap IPv6 failed: %w", err)
	}

	dstIA := addr.MustIAFrom(addr.ISD(isd), addr.AS(asn))

	srcIA := t.localIA
	if srcIA == 0 {
		log.Printf("[IA-MAP] localIA not configured dstIP=%s dstIA=%s", ipString(dstIP), dstIA)
		return 0, 0, fmt.Errorf("localIA not configured")
	}

	log.Printf("[IA-MAP] success dstIP=%s srcIA=%s dstIA=%s isd=%d asn=%d localPrefix=%d subnet=%d host=%s hostIsIPv4=%v",
		ipString(dstIP),
		srcIA,
		dstIA,
		isd,
		asn,
		localPrefix,
		subnet,
		ipString(host),
		hostIsIPv4,
	)

	return srcIA, dstIA, nil
}

func ipToNetip(ip net.IP) (netip.Addr, error) {
	if ip4 := ip.To4(); ip4 != nil {
		var a4 [4]byte
		copy(a4[:], ip4)
		return netip.AddrFrom4(a4), nil
	}

	ip16 := ip.To16()
	if ip16 == nil {
		return netip.Addr{}, fmt.Errorf("invalid IP: %v", ip)
	}
	var a16 [16]byte
	copy(a16[:], ip16)
	return netip.AddrFrom16(a16), nil
}

type Translator struct {
	cache   PathPool
	localIA addr.IA
	brAddr  *net.UDPAddr

	ifaceName string

	wgSrcIPMu sync.RWMutex
	wgSrcIP   net.IP

	dispatchedPorts DispatchPortRange
}

func (t *Translator) SetDispatchedPorts(r DispatchPortRange) {
	t.dispatchedPorts = r
}

func NewTranslator(cache PathPool, localIA addr.IA, brAddr *net.UDPAddr, ifaceName string) *Translator {
	return &Translator{
		cache:     cache,
		localIA:   localIA,
		brAddr:    brAddr,
		ifaceName: ifaceName,
	}
}

const (
	// SCION-mapped IPv6 prefix = fc00::/8
	SCIONPrefixFirstByte = 0xfc
)

type PathPool interface {
	Get(ctx context.Context, srcIA, dstIA addr.IA) ([]pathpool.CachedPath, error)
}

func (t *Translator) ReadOutboundPacket(pkt []byte, dstIP net.IP, srcIP net.IP, hostPort int, isIPv6 bool) ([]byte, error) {
	log.Printf("[READ-OUTBOUND] enter pkt=%s srcIP=%s dstIP=%s hostPort=%d isIPv6=%v localIA=%s brAddr=%s",
		packetSummary(pkt),
		ipString(srcIP),
		ipString(dstIP),
		hostPort,
		isIPv6,
		t.localIA,
		udpAddrString(t.brAddr),
	)

	if !isIPv6 {
		log.Printf("[READ-OUTBOUND] bypass normal IPv4 packet dstIP=%s pktLen=%d",
			ipString(dstIP),
			len(pkt),
		)
		return pkt, nil
	}

	if !IsSCIONMapped(dstIP) {
		log.Printf("[READ-OUTBOUND] bypass: dstIP is not SCION-mapped dstIP=%s pktLen=%d",
			ipString(dstIP),
			len(pkt),
		)
		return pkt, nil
	}

	log.Printf("[READ-OUTBOUND] SCION-mapped destination detected dstIP=%s", ipString(dstIP))

	log.Printf("HIER müssen wir eigentlich schon als srcIP die IP des WG Interface übergeben.")
	newpkt, nextHop, err := t.TranslateEgress(pkt, srcIP, hostPort, nil)
	if err != nil {
		log.Printf("[READ-OUTBOUND] TranslateEgress failed srcIP=%s dstIP=%s hostPort=%d err=%v",
			ipString(srcIP),
			ipString(dstIP),
			hostPort,
			err,
		)
		return pkt, fmt.Errorf("TranslateEgress failed: %w", err)
	}

	log.Printf("[READ-OUTBOUND] translated successfully originalLen=%d translatedLen=%d nextHop=%s",
		len(pkt),
		len(newpkt),
		udpAddrString(nextHop),
	)

	return newpkt, nil
}

func (t *Translator) getPathFromCache(srcIA, dstIA addr.IA) (path.Path, error) {
	log.Printf("[PATHLOOKUP] enter srcIA=%s dstIA=%s", srcIA, dstIA)

	if srcIA == dstIA {
		log.Printf("[PATHLOOKUP] same-AS traffic detected srcIA=%s dstIA=%s using empty path", srcIA, dstIA)
		return path.Path{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	log.Printf("[PATHLOOKUP] cache.Get start srcIA=%s dstIA=%s timeout=2s", srcIA, dstIA)

	CachedPaths, err := t.cache.Get(ctx, srcIA, dstIA)
	elapsed := time.Since(start)

	if err != nil {
		log.Printf("[PATHLOOKUP] cache.Get failed srcIA=%s dstIA=%s elapsed=%s err=%v",
			srcIA,
			dstIA,
			elapsed,
			err,
		)
		return path.Path{}, fmt.Errorf("path cache error for %s -> %s: %w", srcIA, dstIA, err)
	}

	log.Printf("[PATHLOOKUP] cache.Get returned srcIA=%s dstIA=%s elapsed=%s count=%d",
		srcIA,
		dstIA,
		elapsed,
		len(CachedPaths),
	)

	if len(CachedPaths) == 0 {
		log.Printf("[PATHLOOKUP] no paths available srcIA=%s dstIA=%s", srcIA, dstIA)
		return path.Path{}, fmt.Errorf("no paths for %s -> %s", srcIA, dstIA)
	}

	for i, cp := range CachedPaths {
		meta := cp.Path.Metadata()

		var expiry time.Time
		var mtu uint16
		var interfaces any

		if meta != nil {
			expiry = meta.Expiry
			mtu = meta.MTU
			interfaces = meta.Interfaces
		}

		log.Printf("[PATHPOOL] candidate path[%d]: src=%s dst=%s fp=%s nextHop=%v expiry=%s mtu=%d interfaces=%v",
			i,
			srcIA,
			dstIA,
			cp.Fingerprint,
			cp.NextHop,
			expiry.Format(time.RFC3339Nano),
			mtu,
			interfaces,
		)
	}

	//Path Selection Criteria
	//Just select first path for now
	selectedcachedpath := selectPath(CachedPaths)

	meta := selectedcachedpath.Path.Metadata()

	var expiry time.Time
	var mtu uint16
	var interfaces any

	if meta != nil {
		expiry = meta.Expiry
		mtu = meta.MTU
		interfaces = meta.Interfaces
	}

	log.Printf("[PATHPOOL] selection strategy=first-valid src=%s dst=%s selectedFingerprint=%s nextHop=%v expiry=%s mtu=%d interfaces=%v available=%d",
		srcIA,
		dstIA,
		selectedcachedpath.Fingerprint,
		selectedcachedpath.NextHop,
		expiry.Format(time.RFC3339Nano),
		mtu,
		interfaces,
		len(CachedPaths),
	)

	log.Printf("[TRANSLATE-EGRESS] selected cached path: srcIA=%s dstIA=%s fp=%s nextHop=%v",
		srcIA, dstIA, selectedcachedpath.Fingerprint, selectedcachedpath.NextHop)

	//Extract snet path.Path including type assertion
	selectedPath, ok := selectedcachedpath.Path.(path.Path)
	if !ok {
		return path.Path{}, fmt.Errorf("path type assertion failed for %s -> %s", srcIA, dstIA)
	}

	return selectedPath, nil
}

func selectPath(paths []pathpool.CachedPath) pathpool.CachedPath {
	return paths[0]
}

type GetPathFunc func(srcIA, dstIA addr.IA) (path.Path, error)

// IPv6 -> SCION
// returns SCION packet bytes and the UDP next-hop to send to if successful
func (t *Translator) TranslateEgress(pktData []byte, hostIP net.IP, hostPort int, getPath GetPathFunc) ([]byte, *net.UDPAddr, error) {
	log.Printf("[TRANSLATE-EGRESS] enter pkt=%s hostIP=%s hostPort=%d localIA=%s brAddr=%s customGetPath=%v",
		packetSummary(pktData),
		ipString(hostIP),
		hostPort,
		t.localIA,
		udpAddrString(t.brAddr),
		getPath != nil,
	)

	packet := gopacket.NewPacket(pktData, layers.LayerTypeIPv6, gopacket.Default)
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer == nil {
		log.Printf("[TRANSLATE-EGRESS] error: not an IPv6 packet pkt=%s", packetSummary(pktData))
		return nil, nil, errors.New("not an IPv6 packet")
	}
	ip6 := ip6Layer.(*layers.IPv6)

	log.Printf("[TRANSLATE-EGRESS] parsed IPv6 src=%s dst=%s nextHeader=%s trafficClass=%d flowLabel=%d hopLimit=%d payloadLen=%d",
		ipString(ip6.SrcIP),
		ipString(ip6.DstIP),
		ip6.NextHeader,
		ip6.TrafficClass,
		ip6.FlowLabel,
		ip6.HopLimit,
		ip6.Length,
	)

	var innerDstPort uint16
	var hasInnerDstPort bool

	// Preserve the IPv6 Flow Label as SCION FlowID
	flowID := uint32(ip6.FlowLabel)

	//Dummy FlowID for now
	//flowID := uint32(0x86c8b) // Für IPv4
	//flowID := uint32(0x71d6d) // Für IPv6

	//Preserve Traffic Class
	tc := ip6.TrafficClass

	// Init Port variable
	var DstPort int
	var _ = DstPort // suppress unused var warning (DstPort used in other code paths)

	if !IsSCIONMapped(ip6.DstIP) {
		return nil, nil, errors.New("dst not in SCION-mapped network")
	}

	isd, asn, _, _, host, hostIsIPv4, err := UnmapIPv6(ip6.DstIP, 8) // subnetBits = 8

	log.Printf(("[TRANSLATE-EGRESS] unmapped host:=%s"), host)

	if err != nil {
		log.Printf("[TRANSLATE-EGRESS] UnmapIPv6 failed dstIP=%s err=%v", ipString(ip6.DstIP), err)
		return nil, nil, fmt.Errorf("unmap IPv6 failed: %w", err)
	}

	log.Printf("[TRANSLATE-EGRESS] unmapped destination mappedDst=%s dstISD=%d dstASN=%d dstHost=%s dstHostIsIPv4=%v",
		ipString(ip6.DstIP),
		isd,
		asn,
		ipString(host),
		hostIsIPv4,
	)

	srcHost := hostIP

	if ip4, err := t.WGSrcIPv4(); err == nil {
		srcHost = ip4
		log.Printf("[TRANSLATE-EGRESS] selected SCION srcHost from WG interface iface=%s srcHost=%s originalPacketSrc=%s",
			t.ifaceName,
			srcHost,
			hostIP,
		)
	} else {
		log.Printf("[TRANSLATE-EGRESS] failed to get WG IPv4, falling back to packet source originalPacketSrc=%s err=%v",
			hostIP,
			err,
		)
	}

	//srcisd, srcasn, _, _, _, _, err := UnmapIPv6(ip6.SrcIP, 8)
	//if err != nil {
	//	return nil, nil, fmt.Errorf("src unmap IPv6 failed: %w", err)
	//}

	//pathBytes, nextHop, ok := pathCache.Lookup(dstIA)
	//if !ok || len(pathBytes) == 0 {
	// return nil, nil, errors.New("no path available for dst IA")
	//fmt.Println("PathCache miss for dst IA, falling back to direct host+port")

	dstIA := addr.IA(addr.MustIAFrom(addr.ISD(isd), addr.AS(asn)))
	//srcIA := addr.IA(addr.MustIAFrom(addr.ISD(srcisd), addr.AS(srcasn)))
	srcIA := t.localIA
	if srcIA == 0 {
		return nil, nil, fmt.Errorf("localIA not configured (t.localIA=%v)", t.localIA)
	}

	log.Printf("[TRANSLATE] srcIA=%s, dstIA=%s\n", srcIA, dstIA)

	//Using the Callback function
	var selectedPath path.Path
	if getPath != nil {
		log.Printf("[TRANSLATE-EGRESS] resolving path using custom getPath srcIA=%s dstIA=%s", srcIA, dstIA)
		selectedPath, err = getPath(srcIA, dstIA)
	} else {
		log.Printf("[TRANSLATE-EGRESS] resolving path using translator cache srcIA=%s dstIA=%s", srcIA, dstIA)
		selectedPath, err = t.getPathFromCache(srcIA, dstIA)
	}

	if err != nil {
		log.Printf("[TRANSLATE-EGRESS] path resolution failed srcIA=%s dstIA=%s err=%v", srcIA, dstIA, err)
		return nil, nil, fmt.Errorf("path unavailable for dst IA: %w", err)
	}

	log.Printf("[TRANSLATE-EGRESS] path resolved srcIA=%s dstIA=%s pathType=%T underlayNextHop=%s dataplaneNil=%v",
		srcIA,
		dstIA,
		selectedPath,
		udpAddrString(selectedPath.UnderlayNextHop()),
		selectedPath.Dataplane() == nil,
	)
	//Return a snet.path.Scion and nexthopfield
	nextHop := selectedPath.UnderlayNextHop()

	log.Printf("[TRANSLATE-EGRESS] Path nextHop: %v", nextHop)
	log.Printf("[TRANSLATE-EGRESS] Host IP from original packet: %v", hostIP)
	log.Printf("[TRANSLATE-EGRESS] srcHost IP from WG Interface, that will be used: %v", srcHost)
	log.Printf("Und hier muss die hostIP eigentlich die IP von unserem WG Interface sein, oder?")
	log.Printf("[TRANSLATE-EGRESS] hostIsIPv4: %v", hostIsIPv4)

	// TODO: NEEDS CHECKING
	var dstHost net.IP
	if hostIsIPv4 {
		dstHost = host.To4()
		if dstHost == nil {
			return nil, nil, fmt.Errorf("decoded IPv4 host is invalid: %s", host)
		}
		log.Printf("[TRANSLATE-EGRESS] decoded IPv4 dstHost=%s", dstHost)
	} else {
		dstHost = host.To16()
		if dstHost == nil {
			return nil, nil, fmt.Errorf("decoded IPv6/interface host is invalid: %s", host)
		}
		log.Printf("[TRANSLATE-EGRESS] decoded IPv6/interface dstHost=%s", dstHost)
	}

	localISD := uint16(srcIA.ISD())
	localASN := uint64(srcIA.AS())
	dstISD := uint16(dstIA.ISD())
	dstASN := uint64(dstIA.AS())

	// extract L4 layer and ensure supported protocols (UDP, TCP)
	nextHeader := ip6.NextHeader
	var l4nextHeader slayers.L4ProtocolType

	var scionBytes []byte

	switch nextHeader {
	case layers.IPProtocolUDP:
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return nil, nil, errors.New("udp layer missing")
		}
		udp := udpLayer.(*layers.UDP)
		log.Printf("[TRANSLATE-EGRESS] L4 UDP detected srcPort=%d dstPort=%d udpPayloadLen=%d appLayerPresent=%v",
			udp.SrcPort,
			udp.DstPort,
			len(udp.Payload),
			packet.ApplicationLayer() != nil,
		)
		l4nextHeader = slayers.L4UDP

		// Build a *fresh* UDP for the inner packet (to avoid sharing state)
		innerUDP := &slayers.UDP{
			SrcPort: uint16(udp.SrcPort),
			DstPort: uint16(udp.DstPort),
		}

		//SrcPort = int(udp.SrcPort)
		DstPort = int(udp.DstPort)

		innerDstPort = uint16(udp.DstPort)
		hasInnerDstPort = true

		// --- FIX: Extract correct payload ---
		var l4Payload []byte
		if app := packet.ApplicationLayer(); app != nil {
			l4Payload = append([]byte(nil), app.Payload()...) // copy
		}
		log.Printf("[TRANSLATE-EGRESS] UDP payload extracted len=%d", len(l4Payload))

		//innerUDP.Payload = appPayload // payload is "TEST"
		scionBytes, err = BuildSCIONPacket(
			localISD, localASN, dstISD, dstASN,
			srcHost, dstHost,
			flowID, tc,
			l4nextHeader, innerUDP, l4Payload,
			selectedPath,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("build scion packet failed: %w", err)
		}
		log.Printf("[TRANSLATE-EGRESS] UDP BuildSCIONPacket success scionLen=%d", len(scionBytes))

	case layers.IPProtocolTCP:
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			return nil, nil, errors.New("tcp layer missing")
		}

		tcp := tcpLayer.(*layers.TCP)
		log.Printf("[TRANSLATE-EGRESS] L4 TCP detected srcPort=%d dstPort=%d seq=%d ack=%d flags=SYN:%v ACK:%v FIN:%v RST:%v PSH:%v window=%d options=%d payloadLen=%d appLayerPresent=%v",
			tcp.SrcPort,
			tcp.DstPort,
			tcp.Seq,
			tcp.Ack,
			tcp.SYN,
			tcp.ACK,
			tcp.FIN,
			tcp.RST,
			tcp.PSH,
			tcp.Window,
			len(tcp.Options),
			len(tcp.Payload),
			packet.ApplicationLayer() != nil,
		)
		l4nextHeader = slayers.L4TCP

		//SrcPort = int(tcp.SrcPort)
		DstPort = int(tcp.DstPort)

		innerDstPort = uint16(tcp.DstPort)
		hasInnerDstPort = true

		innerTCP := &layers.TCP{
			SrcPort: tcp.SrcPort,
			DstPort: tcp.DstPort,
			Seq:     tcp.Seq,
			Ack:     tcp.Ack,
			SYN:     tcp.SYN,
			ACK:     tcp.ACK,
			FIN:     tcp.FIN,
			RST:     tcp.RST,
			PSH:     tcp.PSH,
			URG:     tcp.URG,
			ECE:     tcp.ECE,
			CWR:     tcp.CWR,
			NS:      tcp.NS,
			Window:  tcp.Window,
			//other flags/options
			Options: tcp.Options,
		}
		//Clamp MSS
		//Todo: Get outer MTU from Interface maybe?
		newMSS := 1100
		for i, opt := range innerTCP.Options {
			if opt.OptionType == layers.TCPOptionKindMSS && len(opt.OptionData) >= 2 {
				oldMSS := binary.BigEndian.Uint16(opt.OptionData[:2])
				opt.OptionData[0] = byte(newMSS >> 8)
				opt.OptionData[1] = byte(newMSS & 0xff)
				innerTCP.Options[i] = opt

				log.Printf("[TRANSLATE-EGRESS] TCP MSS clamped oldMSS=%d newMSS=%d optionIndex=%d",
					oldMSS,
					newMSS,
					i,
				)
			}
		}

		var l4Payload []byte
		if app := packet.ApplicationLayer(); app != nil {
			l4Payload = append([]byte(nil), app.Payload()...) // copy
		}
		log.Printf("[TRANSLATE-EGRESS] TCP payload extracted len=%d", len(l4Payload))

		scionBytes, err = BuildSCIONPacket(localISD, localASN, dstISD, dstASN, srcHost, dstHost, flowID, tc, l4nextHeader, innerTCP, l4Payload, selectedPath)
		if err != nil {
			return nil, nil, fmt.Errorf("build scion packet failed: %w", err)
		}
		log.Printf("[TRANSLATE-EGRESS] TCP BuildSCIONPacket success scionLen=%d", len(scionBytes))

	case layers.IPProtocolICMPv6: // 58
		icmpLayer := packet.Layer(layers.LayerTypeICMPv6)
		if icmpLayer == nil {
			return nil, nil, errors.New("ICMPv6 layer missing")
		}
		icmp := icmpLayer.(*layers.ICMPv6)
		log.Printf("[TRANSLATE-EGRESS] L4 ICMPv6 detected typeCode=%v payloadLen=%d appLayerPresent=%v",
			icmp.TypeCode,
			len(icmp.Payload),
			packet.ApplicationLayer() != nil,
		)
		l4nextHeader = slayers.L4SCMP

		scmpPayload := append([]byte(nil), icmp.Payload...)

		scmpTypeCode := translateICMPv6ToSCMPTypeCode(icmp.TypeCode)
		log.Printf("[TRANSLATE-EGRESS] ICMPv6 translated to SCMP icmpTypeCode=%v scmpTypeCode=%v scmpPayloadLen=%d",
			icmp.TypeCode,
			scmpTypeCode,
			len(scmpPayload),
		)

		scmp := &slayers.SCMP{
			TypeCode: scmpTypeCode,
		}

		scionBytes, err = BuildSCIONPacket(
			localISD, localASN, dstISD, dstASN,
			srcHost, dstHost,
			flowID, tc,
			l4nextHeader, scmp, scmpPayload,
			selectedPath,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("build scion packet failed: %w", err)
		}
		log.Printf("[TRANSLATE-EGRESS] SCMP BuildSCIONPacket success scionLen=%d", len(scionBytes))

	default:
		return nil, nil, fmt.Errorf("unsupported upper-layer protocol: %d", nextHeader)
	}

	//scionBytes = [ SCION header | SCION L4 payload ]

	//Wrap Scion Bytes in IP and UDP before returning

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// If pathBytes encode an "empty path", the PathCache implementation could
	// return nextHop==nil — in that case we need to send to the Border Router
	// for proper SCION delivery, not the tunnel peer address.
	if nextHop == nil {
		if srcIA == dstIA {
			port := chooseSameASDispatchPort(
				innerDstPort,
				hasInnerDstPort,
				uint16(hostPort),
				t.dispatchedPorts,
			)

			nextHop = &net.UDPAddr{
				IP:   dstHost,
				Port: int(port),
			}

			log.Printf(
				"[TRANSLATE-EGRESS] same-AS empty path, using direct dst host nextHop=%s selectedPort=%d innerDstPort=%d hasInnerDstPort=%v hostPort=%d dispatched=%d-%d valid=%v",
				nextHop.String(),
				port,
				innerDstPort,
				hasInnerDstPort,
				uint16(hostPort),
				t.dispatchedPorts.Start,
				t.dispatchedPorts.End,
				t.dispatchedPorts.Valid,
			)
		} else {
			return nil, nil, fmt.Errorf("no nextHop for non-local path srcIA=%s dstIA=%s", srcIA, dstIA)
		}
	}
	log.Printf("[TRANSLATE-EGRESS] preparing outer encapsulation nextHop=%s nextHopIPv4=%v scionLen=%d",
		udpAddrString(nextHop),
		nextHop != nil && nextHop.IP.To4() != nil,
		len(scionBytes),
	)
	// hostIsIPv4 - check nextHop's address family since that's what we're sending to
	// For IPv4 underlay, we need an IPv4 source (underlay IP), not the TUN IP
	if nextHop.IP.To4() != nil {
		// Use underlay IPv4 address as source (e.g., 10.0.0.2 for client side)
		// When sending to nextHop (127.0.0.x loopback), use loopback or underlay IP
		srcIP := srcHost
		if srcHost.To4() == nil {
			// hostIP is IPv6 (e.g., fd00::2), use the underlay IP for IPv4 packet
			// In test env, client's underlay is 10.0.0.2
			srcIP = net.ParseIP("10.0.0.2")
			log.Printf("[TRANSLATE-EGRESS] srcHost is not IPv4, falling back to hardcoded IPv4 srcIP=%s originalHostIP=%s",
				ipString(srcIP),
				ipString(srcHost),
			)
		}
		// -------- IPv4 underlay --------
		ip4 := &layers.IPv4{
			Version:  4,
			IHL:      5,                       // standard 20-byte header
			TOS:      0x20,                    // match expected TOS
			Flags:    layers.IPv4DontFragment, // DF flag set
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    srcIP.To4(),
			DstIP:    nextHop.IP.To4(),
		}

		udp := &layers.UDP{
			SrcPort: layers.UDPPort(hostPort),
			DstPort: layers.UDPPort(nextHop.Port),
		}
		udp.SetNetworkLayerForChecksum(ip4)
		log.Printf("[TRANSLATE-EGRESS] outer IPv4/UDP src=%s:%d dst=%s:%d tos=0x%02x ttl=%d df=%v payloadLen=%d",
			ipString(srcIP.To4()),
			hostPort,
			ipString(nextHop.IP.To4()),
			nextHop.Port,
			ip4.TOS,
			ip4.TTL,
			ip4.Flags&layers.IPv4DontFragment != 0,
			len(scionBytes),
		)
		if err := gopacket.SerializeLayers(buf, opts,
			ip4,
			udp,
			gopacket.Payload(scionBytes),
		); err != nil {
			return nil, nil, fmt.Errorf("failed to serialize IPv4/UDP+SCION: %w", err)
		}
		log.Printf("[TRANSLATE-EGRESS] outer IPv4/UDP serialization success outerLen=%d", len(buf.Bytes()))
	} else {

		srcIP := net.ParseIP("10.0.0.2")
		log.Printf("[TRANSLATE-EGRESS] Falling back to hardcoded IPv4 srcIP=%s originalHostIP=%s",
			ipString(srcIP),
			ipString(hostIP),
		)
		// -------- IPv6 underlay --------
		ip6Under := &layers.IPv6{
			Version:      6,
			TrafficClass: tc,
			FlowLabel:    ip6.FlowLabel,
			HopLimit:     64,
			NextHeader:   layers.IPProtocolUDP,
			SrcIP:        srcIP,
			DstIP:        nextHop.IP,
		}

		//Muss hostPort sein. Um zwischen SCION und normal zu unterscheiden
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(hostPort),
			DstPort: layers.UDPPort(nextHop.Port),
		}
		udp.SetNetworkLayerForChecksum(ip6Under)
		log.Printf("[TRANSLATE-EGRESS] outer IPv6/UDP src=%s:%d dst=%s:%d trafficClass=%d flowLabel=%d hopLimit=%d payloadLen=%d",
			ipString(ip6Under.SrcIP),
			hostPort,
			ipString(ip6Under.DstIP),
			nextHop.Port,
			ip6Under.TrafficClass,
			ip6Under.FlowLabel,
			ip6Under.HopLimit,
			len(scionBytes),
		)
		if err := gopacket.SerializeLayers(buf, opts,
			ip6Under,
			udp,
			gopacket.Payload(scionBytes),
		); err != nil {
			return nil, nil, fmt.Errorf("failed to serialize IPv6/UDP+SCION: %w", err)
		}
		log.Printf("[TRANSLATE-EGRESS] outer IPv6/UDP serialization success outerLen=%d", len(buf.Bytes()))
	}

	//Outer = [ IPv4 header | UDP header | SCION header | SCION L4 payload ]
	//We need TCP Out the same
	outer := buf.Bytes()

	log.Printf("[TRANSLATE-EGRESS] exit success outerLen=%d nextHop=%s dstIA=%s hostDst=%s l4=%v",
		len(outer),
		udpAddrString(nextHop),
		dstIA,
		ipString(dstHost),
		nextHeader,
	)

	return outer, nextHop, nil

}

// SCION -> IPv6
func (t *Translator) TranslateIngress(pktData []byte, tunIP net.IP) ([]byte, error) {
	log.Printf("[TRANSLATE-INGRESS] enter pkt=%s tunIP=%s localIA=%s",
		packetSummary(pktData),
		ipString(tunIP),
		t.localIA,
	)

	if len(pktData) == 0 {
		log.Printf("[TRANSLATE-INGRESS] error: empty packet")
		return nil, fmt.Errorf("empty packet")
	}
	//------------------------- Parse outer IP (v4 or v6) + UDP -----------------
	firstNibble := pktData[0] >> 4

	var pkt gopacket.Packet

	switch firstNibble {
	case 4:
		pkt = gopacket.NewPacket(pktData, layers.LayerTypeIPv4, gopacket.Default)

		ip4Layer := pkt.Layer(layers.LayerTypeIPv4)
		if ip4Layer == nil {
			return pktData, nil
		}

		ip4 := ip4Layer.(*layers.IPv4)
		if ip4.Protocol != layers.IPProtocolUDP {
			return pktData, nil
		}

	case 6:
		pkt = gopacket.NewPacket(pktData, layers.LayerTypeIPv6, gopacket.Default)

		ip6Layer := pkt.Layer(layers.LayerTypeIPv6)
		if ip6Layer == nil {
			return pktData, nil
		}

		ip6 := ip6Layer.(*layers.IPv6)

		// Normal IPv6 should also bypass unless it is UDP carrying SCION.
		if ip6.NextHeader != layers.IPProtocolUDP {
			return pktData, nil
		}

	default:
		return pktData, nil
	}

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return pktData, nil
	}

	udpOuter := udpLayer.(*layers.UDP)

	/* 	// Optional: only SCION/dispatcher/BR ports should be translated.
	   	// Everything else should stay normal WG traffic.
	   	if udpOuter.DstPort != 30041 && udpOuter.SrcPort != 30041 &&
	   		udpOuter.DstPort != 50000 && udpOuter.SrcPort != 50000 {
	   		log.Printf("[TRANSLATE-INGRESS] bypass UDP packet not recognized as SCION srcPort=%d dstPort=%d",
	   			udpOuter.SrcPort,
	   			udpOuter.DstPort,
	   		)
	   		return pktData, nil
	   	} */

	log.Printf("[TRANSLATE-INGRESS] outer UDP srcPort=%d dstPort=%d payloadLen=%d",
		udpOuter.SrcPort,
		udpOuter.DstPort,
		len(udpOuter.Payload),
	)

	scionPayload := udpOuter.Payload
	if len(scionPayload) == 0 {
		return nil, fmt.Errorf("no SCION payload in outer UDP")
	}

	// ---------------------- Decode Scion -------------------

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
		log.Printf("[TRANSLATE-INGRESS] SCION decode failed or unsupported sublayer srcPort=%d dstPort=%d payloadLen=%d decoded=%v err=%v",
			udpOuter.SrcPort,
			udpOuter.DstPort,
			len(scionPayload),
			decoded,
			err,
		)
		return pktData, nil
	}

	log.Printf("[TRANSLATE-INGRESS] SCION decoded layers=%v srcIA=%s dstIA=%s srcAddrType=%v dstAddrType=%v flowID=%d trafficClass=%d nextHdr=%v rawSrc=%v rawDst=%v",
		decoded,
		scn.SrcIA,
		scn.DstIA,
		scn.SrcAddrType,
		scn.DstAddrType,
		scn.FlowID,
		scn.TrafficClass,
		scn.NextHdr,
		net.IP(scn.RawSrcAddr),
		net.IP(scn.RawDstAddr),
	)

	var l4Layer gopacket.SerializableLayer
	var l4Payload []byte

	var forceIPv6 bool

	//Assiging layers Scion, UDP or TCP and Payload
	for _, layerType := range decoded {
		// Handle layers
		switch layerType {
		case slayers.LayerTypeSCION:
			continue
		case slayers.LayerTypeSCIONUDP:
			// L4 Layer is UDP
			l4Layer = &udp
			l4Payload = []byte(pld)

		case slayers.LayerTypeSCMP:
			// For SCMP Echo, the bytes after the SCMP header are basically the echo-info:
			// identifier + sequence + echo data
			// We can reuse SCMP payload as ICMP payload: SCION / SCMP / SCMPEcho / data -> IPv6 / ICMPv6 / echo-info / data
			scmpPayload := append([]byte(nil), scmp.LayerPayload()...)

			// Fallback, in case gopacket put something into pld.
			if len(scmpPayload) == 0 && len(pld) > 0 {
				scmpPayload = append([]byte(nil), []byte(pld)...)
			}

			log.Printf("[TRANSLATE-INGRESS] SCMP received typeCode=%v infoMsg=%v scmpPayloadLen=%d rawPayloadLen=%d",
				scmp.TypeCode,
				scmp.TypeCode.InfoMsg(),
				len(scmpPayload),
				len(pld),
			)

			icmpTypeCode := translateSCMPTypeCodeToICMPv6(scmp.TypeCode)

			icmp := &layers.ICMPv6{
				TypeCode: icmpTypeCode,
			}

			l4Layer = icmp
			l4Payload = scmpPayload
			forceIPv6 = true

			log.Printf("[TRANSLATE-INGRESS] SCMP translated to ICMPv6 scmpTypeCode=%v icmpTypeCode=%v icmpPayloadLen=%d",
				scmp.TypeCode,
				icmpTypeCode,
				len(l4Payload),
			)
		case layers.LayerTypeTCP:

			log.Printf("[TRANSLATE-INGRESS] inner TCP decoded srcPort=%d dstPort=%d seq=%d ack=%d SYN=%v ACK=%v FIN=%v RST=%v PSH=%v window=%d options=%d payloadLen=%d",
				tcp.SrcPort,
				tcp.DstPort,
				tcp.Seq,
				tcp.Ack,
				tcp.SYN,
				tcp.ACK,
				tcp.FIN,
				tcp.RST,
				tcp.PSH,
				tcp.Window,
				len(tcp.Options),
				len(tcp.Payload),
			)

			l4Layer = &tcp
			l4Payload = append([]byte(nil), tcp.Payload...)

		case gopacket.LayerTypePayload:
			//This will be the leftover case - No UDP or SCMP -> Can we assume it is TCP then?
			// L4 Layer Payload
			//l4Payload = []byte(pld)
		default:
			return nil, fmt.Errorf("unknow layertype")
		}

	}

	if l4Layer == nil && scn.NextHdr == slayers.L4TCP {
		raw := []byte(pld)

		log.Printf("[TRANSLATE-INGRESS] fallback TCP decode rawLen=%d", len(raw))

		if err := tcp.DecodeFromBytes(raw, gopacket.NilDecodeFeedback); err != nil {
			return nil, fmt.Errorf("failed to decode fallback inner TCP: %w", err)
		}

		l4Layer = &tcp
		l4Payload = append([]byte(nil), tcp.Payload...)
	}

	// ---------------------------- Map SCION dst/src host -> IP -----------------------
	var dst, src net.IP

	islocal := false
	if scn.DstIA == scn.SrcIA {
		islocal = true
	}

	// ---- dst ----
	isd := int(scn.DstIA.ISD())
	asn := addr_translation.ASN{Value: uint64(scn.DstIA.AS())}
	iface := net.IP(scn.RawDstAddr)

	switch scn.DstAddrType {
	case slayers.T4Ip:
		if islocal {
			dst = net.IP(scn.RawDstAddr)
		} else {
			//Then it needs to be mapped to a IPv6 Address
			var err error
			dst, err = addr_translation.ScionToIP(isd, asn, 0, 0, iface, 8)
			if err != nil {
				return nil, fmt.Errorf("ScionToIP failed: %w", err)
			}
		}
	case slayers.T16Ip:
		iface := net.IP(scn.RawDstAddr)

		if islocal {
			if IsSCIONMapped(iface) {
				_, _, _, _, hostIP, _, err := UnmapIPv6(iface, 8)
				if err != nil {
					return nil, fmt.Errorf("unmap dst SCION-mapped IPv6 failed: %w", err)
				}
				dst = hostIP
			} else {
				dst = iface.To16()
			}
		} else {
			var err error
			dst, err = addr_translation.ScionToIP(isd, asn, 0, 0, iface, 8)
			if err != nil {
				return nil, fmt.Errorf("ScionToIP dst T16 failed: %w", err)
			}
		}
	default:
		return nil, errors.New("unsupported destination host type")
	}

	// must match tunnel endpoint
	//if !dst.Equal(tunIP) {
	//return nil, errors.New("packet not for this tunnel endpoint")
	//}
	isd = int(scn.SrcIA.ISD())
	asn = addr_translation.ASN{Value: uint64(scn.SrcIA.AS())}
	iface = net.IP(scn.RawSrcAddr)

	// ---- src ----
	switch scn.SrcAddrType {
	case slayers.T4Ip:
		//Only if ASN of src and dst are the same - bool local
		if islocal {
			src = net.IP(scn.RawSrcAddr)
		} else {
			//Then it needs to be mapped to a IPv6 Address
			var err error
			src, err = addr_translation.ScionToIP(isd, asn, 0, 0, iface, 8)
			if err != nil {
				return nil, fmt.Errorf("ScionToIP failed: %w", err)
			}
		}

	case slayers.T16Ip:
		iface := net.IP(scn.RawSrcAddr)

		if islocal {
			if IsSCIONMapped(iface) {
				_, _, _, _, hostIP, _, err := UnmapIPv6(iface, 8)
				if err != nil {
					return nil, fmt.Errorf("unmap src SCION-mapped IPv6 failed: %w", err)
				}
				src = hostIP
			} else {
				src = iface.To16()
			}
		} else {
			var err error
			src, err = addr_translation.ScionToIP(isd, asn, 0, 0, iface, 8)
			if err != nil {
				return nil, fmt.Errorf("ScionToIP src T16 failed: %w", err)
			}
		}
	default:
		return nil, errors.New("unsupported source host type")
	}

	log.Printf("[TRANSLATE-INGRESS] mapped SCION hosts to IP src=%s dst=%s isLocal=%v",
		ipString(src),
		ipString(dst),
		islocal,
	)

	// --- Force IPv6

	if forceIPv6 {
		srcMapped, err := addr_translation.ScionToIP(
			int(scn.SrcIA.ISD()),
			addr_translation.ASN{Value: uint64(scn.SrcIA.AS())},
			0,
			0,
			net.IP(scn.RawSrcAddr),
			8,
		)
		if err != nil {
			return nil, fmt.Errorf("SCMP ingress map src to SCION-mapped IPv6 failed: %w", err)
		}

		dstLocal := tunIP
		if dstLocal == nil || dstLocal.To4() != nil || dstLocal.To16() == nil {
			dstLocal, err = IPv6OfInterface(t.ifaceName)
			if err != nil {
				return nil, fmt.Errorf("SCMP ingress could not determine local tunnel IPv6: %w", err)
			}
		}

		src = srcMapped
		dst = dstLocal.To16()

		log.Printf("[TRANSLATE-INGRESS] force IPv6 for SCMP/ICMP srcMapped=%s dstLocal=%s iface=%s",
			ipString(src),
			ipString(dst),
			t.ifaceName,
		)
	}

	// ---- Build IP Packet ----

	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Return nil if not IPv4 Adr
	dst4 := dst.To4()
	src4 := src.To4()

	//If both Src and Dst are IPv4, build IPv4 Packet
	if dst4 != nil && src4 != nil {

		log.Printf("[TRANSLATE-INGRESS] rebuilding inner IPv4 packet src=%s dst=%s l4Type=%T payloadLen=%d",
			ipString(src4),
			ipString(dst4),
			l4Layer,
			len(l4Payload),
		)

		// -------- Build IPv4 packet --------
		ip4 := &layers.IPv4{
			Version: 4,
			IHL:     5,
			TTL:     64,
			//Protocol: layers.IPProtocol(l4Layer.LayerType().LayerTypes()[0]),
			SrcIP: src4,
			DstIP: dst4,
		}

		// set checksum network layer for UDP/TCP
		switch l4Layer.(type) {
		case *slayers.UDP:
			ip4.Protocol = layers.IPProtocolUDP

			inner := &layers.UDP{
				SrcPort: layers.UDPPort(udp.SrcPort),
				DstPort: layers.UDPPort(udp.DstPort),
			}
			inner.SetNetworkLayerForChecksum(ip4)

			log.Printf("[TRANSLATE-INGRESS] serializing IPv4/UDP src=%s dst=%s srcPort=%d dstPort=%d payloadLen=%d",
				ipString(ip4.SrcIP),
				ipString(ip4.DstIP),
				udp.SrcPort,
				udp.DstPort,
				len(l4Payload),
			)

			if err := gopacket.SerializeLayers(
				buf,
				opts,
				ip4,
				inner,
				gopacket.Payload(l4Payload),
			); err != nil {
				return nil, fmt.Errorf("failed to serialize IPv4/UDP: %w", err)
			}

			out := buf.Bytes()
			log.Printf("[TRANSLATE-INGRESS] IPv4/UDP serialization success len=%d", len(out))
			return out, nil

		case *layers.TCP:
			ip4.Protocol = layers.IPProtocolTCP

			inner := &layers.TCP{
				SrcPort: layers.TCPPort(tcp.SrcPort),
				DstPort: layers.TCPPort(tcp.DstPort),
				Seq:     tcp.Seq,
				Ack:     tcp.Ack,
				SYN:     tcp.SYN,
				ACK:     tcp.ACK,
				FIN:     tcp.FIN,
				RST:     tcp.RST,
				PSH:     tcp.PSH,
				URG:     tcp.URG,
				ECE:     tcp.ECE,
				CWR:     tcp.CWR,
				NS:      tcp.NS,
				Window:  tcp.Window,
				Options: tcp.Options,
			}

			inner.SetNetworkLayerForChecksum(ip4)

			log.Printf("[TRANSLATE-INGRESS] serializing IPv4/TCP src=%s dst=%s srcPort=%d dstPort=%d seq=%d ack=%d SYN=%v ACK=%v FIN=%v RST=%v PSH=%v window=%d options=%d payloadLen=%d",
				ipString(ip4.SrcIP),
				ipString(ip4.DstIP),
				inner.SrcPort,
				inner.DstPort,
				inner.Seq,
				inner.Ack,
				inner.SYN,
				inner.ACK,
				inner.FIN,
				inner.RST,
				inner.PSH,
				inner.Window,
				len(inner.Options),
				len(l4Payload),
			)

			if err := gopacket.SerializeLayers(
				buf,
				opts,
				ip4,
				inner,
				gopacket.Payload(l4Payload),
			); err != nil {
				return nil, fmt.Errorf("failed to serialize IPv4/TCP: %w", err)
			}

			out := buf.Bytes()
			log.Printf("[TRANSLATE-INGRESS] IPv4/TCP serialization success len=%d", len(out))
			return out, nil

		}

	} else {

		log.Printf("[TRANSLATE-INGRESS] rebuilding inner IPv6 packet src=%s dst=%s l4Type=%T payloadLen=%d flowID=%d trafficClass=%d",
			ipString(src),
			ipString(dst),
			l4Layer,
			len(l4Payload),
			scn.FlowID,
			scn.TrafficClass,
		)
		// ---- Build IPv6 ----
		ip6 := &layers.IPv6{
			Version: 6,
			SrcIP:   src,
			DstIP:   dst,
			//NextHeader:   layers.IPProtocol(l4Layer.LayerType().LayerTypes()[0]),
			HopLimit:     64,
			FlowLabel:    scn.FlowID,
			TrafficClass: scn.TrafficClass,
		}

		// set checksum network layer for UDP/TCP
		switch l4Layer.(type) {
		case *slayers.UDP:
			//	l.SetNetworkLayerForChecksum(ip4)
			ip6.NextHeader = layers.IPProtocolUDP
			// Convert slayers.UDP (SCION UDP) -> normal IP UDP
			innerUDP := &layers.UDP{
				SrcPort: layers.UDPPort(udp.SrcPort),
				DstPort: layers.UDPPort(udp.DstPort),
			}

			// Tell UDP which network layer to use for checksum
			innerUDP.SetNetworkLayerForChecksum(ip6)

			if err := gopacket.SerializeLayers(
				buf,
				opts,
				ip6,
				innerUDP,
				gopacket.Payload(l4Payload),
			); err != nil {
				return nil, fmt.Errorf("failed to serialize IPv6: %w", err)
			}
			return buf.Bytes(), nil

		case *layers.TCP:
			//	l.SetNetworkLayerForChecksum(ip4)
			ip6.NextHeader = layers.IPProtocolTCP
			// Convert slayers.UDP (SCION UDP) -> normal IP UDP
			innerTCP := &layers.TCP{
				SrcPort: layers.TCPPort(tcp.SrcPort),
				DstPort: layers.TCPPort(tcp.DstPort),
				Seq:     tcp.Seq,
				Ack:     tcp.Ack,
				SYN:     tcp.SYN,
				ACK:     tcp.ACK,
				FIN:     tcp.FIN,
				RST:     tcp.RST,
				PSH:     tcp.PSH,
				URG:     tcp.URG,
				ECE:     tcp.ECE,
				CWR:     tcp.CWR,
				NS:      tcp.NS,
				Window:  tcp.Window,
				Options: tcp.Options,
			}

			//Compute and Modify MSS
			for i, opt := range innerTCP.Options {
				if opt.OptionType == layers.TCPOptionKindMSS {
					newMSS := computeMSS(1480) // or device MTU
					opt.OptionData = []byte{byte(newMSS >> 8), byte(newMSS)}
					innerTCP.Options[i] = opt
				}
			}

			// Tell UDP which network layer to use for checksum
			innerTCP.SetNetworkLayerForChecksum(ip6)

			if err := gopacket.SerializeLayers(
				buf,
				opts,
				ip6,
				innerTCP,
				gopacket.Payload(l4Payload),
			); err != nil {
				return nil, fmt.Errorf("failed to serialize IPv6: %w", err)
			}
			return buf.Bytes(), nil

		case *layers.ICMPv6:
			ip6.NextHeader = layers.IPProtocolICMPv6

			innerICMP := l4Layer.(*layers.ICMPv6)
			innerICMP.SetNetworkLayerForChecksum(ip6)

			log.Printf("[TRANSLATE-INGRESS] serializing IPv6/ICMPv6 src=%s dst=%s typeCode=%v payloadLen=%d",
				ipString(ip6.SrcIP),
				ipString(ip6.DstIP),
				innerICMP.TypeCode,
				len(l4Payload),
			)

			if err := gopacket.SerializeLayers(
				buf,
				opts,
				ip6,
				innerICMP,
				gopacket.Payload(l4Payload),
			); err != nil {
				return nil, fmt.Errorf("failed to serialize IPv6/ICMPv6: %w", err)
			}

			out := buf.Bytes()
			log.Printf("[TRANSLATE-INGRESS] IPv6/ICMPv6 serialization success len=%d", len(out))
			return out, nil
		}

	}
	out := buf.Bytes()
	if len(out) == 0 {
		return nil, fmt.Errorf("no packet serialized for l4Type=%T src=%s dst=%s", l4Layer, src, dst)
	}

	log.Printf("[TRANSLATE-INGRESS] exit success rebuiltLen=%d src=%s dst=%s l4Type=%T",
		len(out),
		ipString(src),
		ipString(dst),
		l4Layer,
	)
	return out, nil

}

// translateICMPv6ToSCMPTypeCode maps ICMPv6 Type+Code to SCMP Type+Code.
func translateICMPv6ToSCMPTypeCode(icmp6TypeCode layers.ICMPv6TypeCode) slayers.SCMPTypeCode {
	log.Printf("[ICMP6->SCMP] enter raw=%v rawUint16=0x%04x type=%d code=%d string=%s",
		icmp6TypeCode,
		uint16(icmp6TypeCode),
		icmp6TypeCode.Type(),
		icmp6TypeCode.Code(),
		icmp6TypeCode.String(),
	)

	var out slayers.SCMPTypeCode

	switch icmp6TypeCode.Type() {
	case layers.ICMPv6TypeDestinationUnreachable:
		switch icmp6TypeCode.Code() {
		case 0:
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable, slayers.SCMPCodeNoRoute)
		case 1:
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable, slayers.SCMPCodeAdminDeny)
		case 2:
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable, slayers.SCMPCodeBeyondScopeOfSourceAddr)
		case 3:
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable, slayers.SCMPCodeAddressUnreachable)
		case 4:
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable, slayers.SCMPCodePortUnreachable)
		case 5:
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable, slayers.SCMPCodeSourceAddressFailedPolicy)
		case 6:
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable, slayers.SCMPCodeRejectRouteToDest)
		default:
			log.Printf("[ICMP6->SCMP] warning: unsupported ICMPv6 DestinationUnreachable code=%d, fallback=NoRoute",
				icmp6TypeCode.Code())
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable, slayers.SCMPCodeNoRoute)
		}

	case layers.ICMPv6TypePacketTooBig:
		out = slayers.CreateSCMPTypeCode(slayers.SCMPTypePacketTooBig, 0)

	case layers.ICMPv6TypeTimeExceeded:
		log.Printf("[ICMP6->SCMP] warning: ICMPv6 TimeExceeded has no direct SCMP equivalent, fallback=DestinationUnreachable(NoRoute)")
		out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable, slayers.SCMPCodeNoRoute)

	case layers.ICMPv6TypeParameterProblem:
		switch icmp6TypeCode.Code() {
		case 0:
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem, slayers.SCMPCodeErroneousHeaderField)
		case 1:
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem, slayers.SCMPCodeUnknownNextHdrType)
		case 2:
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem, slayers.SCMPCodeUnknownHopByHopOption)
		default:
			log.Printf("[ICMP6->SCMP] warning: unsupported ICMPv6 ParameterProblem code=%d, fallback=ErroneousHeaderField",
				icmp6TypeCode.Code())
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem, slayers.SCMPCodeErroneousHeaderField)
		}

	case layers.ICMPv6TypeEchoRequest:
		out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoRequest, 0)

	case layers.ICMPv6TypeEchoReply:
		out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoReply, 0)

	default:
		log.Printf("[ICMP6->SCMP] warning: unsupported ICMPv6 type=%d code=%d string=%s, fallback=DestinationUnreachable(NoRoute)",
			icmp6TypeCode.Type(),
			icmp6TypeCode.Code(),
			icmp6TypeCode.String(),
		)
		out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable, slayers.SCMPCodeNoRoute)
	}

	log.Printf("[ICMP6->SCMP] exit in=%s(type=%d code=%d raw=0x%04x) -> out=%s(type=%d code=%d raw=0x%04x)",
		icmp6TypeCode.String(),
		icmp6TypeCode.Type(),
		icmp6TypeCode.Code(),
		uint16(icmp6TypeCode),
		out.String(),
		out.Type(),
		out.Code(),
		uint16(out),
	)

	return out
}

// translateSCMPTypeCodeToICMPv6 maps SCMP Type+Code back to ICMPv6 Type+Code.
func translateSCMPTypeCodeToICMPv6(scmpTypeCode slayers.SCMPTypeCode) layers.ICMPv6TypeCode {
	log.Printf("[SCMP->ICMP6] enter raw=%v rawUint16=0x%04x type=%d code=%d string=%s infoMsg=%v",
		scmpTypeCode,
		uint16(scmpTypeCode),
		scmpTypeCode.Type(),
		scmpTypeCode.Code(),
		scmpTypeCode.String(),
		scmpTypeCode.InfoMsg(),
	)

	var out layers.ICMPv6TypeCode

	switch scmpTypeCode.Type() {
	case slayers.SCMPTypeDestinationUnreachable:
		switch scmpTypeCode.Code() {
		case slayers.SCMPCodeNoRoute:
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 0)
		case slayers.SCMPCodeAdminDeny:
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 1)
		case slayers.SCMPCodeBeyondScopeOfSourceAddr:
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 2)
		case slayers.SCMPCodeAddressUnreachable:
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 3)
		case slayers.SCMPCodePortUnreachable:
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 4)
		case slayers.SCMPCodeSourceAddressFailedPolicy:
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 5)
		case slayers.SCMPCodeRejectRouteToDest:
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 6)
		default:
			log.Printf("[SCMP->ICMP6] warning: unsupported SCMP DestinationUnreachable code=%d, fallback=ICMPv6 NoRoute",
				scmpTypeCode.Code())
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 0)
		}

	case slayers.SCMPTypePacketTooBig:
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypePacketTooBig, 0)

	case slayers.SCMPTypeParameterProblem:
		switch scmpTypeCode.Code() {
		case slayers.SCMPCodeErroneousHeaderField:
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 0)
		case slayers.SCMPCodeUnknownNextHdrType:
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 1)
		case slayers.SCMPCodeUnknownHopByHopOption:
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 2)
		case slayers.SCMPCodeUnknownEndToEndOption:
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 2)

		case slayers.SCMPCodeInvalidCommonHeader,
			slayers.SCMPCodeUnknownSCIONVersion,
			slayers.SCMPCodeFlowIDRequired,
			slayers.SCMPCodeInvalidPacketSize,
			slayers.SCMPCodeUnknownPathType,
			slayers.SCMPCodeUnknownAddressFormat,
			slayers.SCMPCodeInvalidAddressHeader,
			slayers.SCMPCodeInvalidSourceAddress,
			slayers.SCMPCodeInvalidDestinationAddress,
			slayers.SCMPCodeNonLocalDelivery,
			slayers.SCMPCodeInvalidPath,
			slayers.SCMPCodeUnknownHopFieldIngress,
			slayers.SCMPCodeUnknownHopFieldEgress,
			slayers.SCMPCodeInvalidHopFieldMAC,
			slayers.SCMPCodePathExpired,
			slayers.SCMPCodeInvalidSegmentChange,
			slayers.SCMPCodeInvalidExtensionHeader:
			log.Printf("[SCMP->ICMP6] info: SCION-specific ParameterProblem code=%d mapped to generic ICMPv6 ParameterProblem code=0",
				scmpTypeCode.Code())
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 0)

		default:
			log.Printf("[SCMP->ICMP6] warning: unsupported SCMP ParameterProblem code=%d, fallback=ICMPv6 ParameterProblem code=0",
				scmpTypeCode.Code())
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 0)
		}

	case slayers.SCMPTypeExternalInterfaceDown:
		log.Printf("[SCMP->ICMP6] info: ExternalInterfaceDown mapped to ICMPv6 DestinationUnreachable NoRoute")
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 0)

	case slayers.SCMPTypeInternalConnectivityDown:
		log.Printf("[SCMP->ICMP6] info: InternalConnectivityDown mapped to ICMPv6 DestinationUnreachable NoRoute")
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 0)

	case slayers.SCMPTypeEchoRequest:
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)

	case slayers.SCMPTypeEchoReply:
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0)

	case slayers.SCMPTypeTracerouteRequest:
		log.Printf("[SCMP->ICMP6] info: TracerouteRequest mapped to ICMPv6 EchoRequest")
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)

	case slayers.SCMPTypeTracerouteReply:
		log.Printf("[SCMP->ICMP6] info: TracerouteReply mapped to ICMPv6 EchoReply")
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0)

	default:
		log.Printf("[SCMP->ICMP6] warning: unsupported SCMP type=%d code=%d string=%s, fallback=ICMPv6 DestinationUnreachable NoRoute",
			scmpTypeCode.Type(),
			scmpTypeCode.Code(),
			scmpTypeCode.String(),
		)
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 0)
	}

	log.Printf("[SCMP->ICMP6] exit in=%s(type=%d code=%d raw=0x%04x) -> out=%s(type=%d code=%d raw=0x%04x)",
		scmpTypeCode.String(),
		scmpTypeCode.Type(),
		scmpTypeCode.Code(),
		uint16(scmpTypeCode),
		out.String(),
		out.Type(),
		out.Code(),
		uint16(out),
	)

	return out
}

// SCMP -> ICMPv6 translation
func scmpToICMP(scmp *slayers.SCMP, scionPayload []byte) ([]byte, error) {
	icmpTypeCode := translateSCMPTypeCodeToICMPv6(scmp.TypeCode)

	icmp := &layers.ICMPv6{
		TypeCode: icmpTypeCode,
	}

	var payload []byte
	if len(scionPayload) > 0 {
		payload = scionPayload
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, icmp, gopacket.Payload(payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize ICMPv6: %w", err)
	}

	return buf.Bytes(), nil
}

// IsSCIONMapped returns true if ip is in fc00::/8
func IsSCIONMapped(ip net.IP) bool {
	return addr_translation.IsSCIONMapped(ip)
}

/*
func UnmapIPv6(ip net.IP, subnetBits uint) (

	uint16,
	uint32,
	uint32,
	uint32,
	net.IP,
	bool,
	error,

)
*/
func UnmapIPv6(ip net.IP, subnetBits uint) (
	uint16,
	uint64,
	uint32,
	uint32,
	net.IP,
	bool,
	error,
) {
	return addr_translation.UnmapIPv6(ip, subnetBits)
}

// This only return scion bytes
func BuildSCIONPacket(
	localISD uint16,
	localASN uint64,
	dstISD uint16,
	dstASN uint64,
	srcHost net.IP,
	dstHost net.IP,
	flowID uint32,
	tc uint8,
	nextHeader slayers.L4ProtocolType,
	l4layer gopacket.SerializableLayer,
	l4Payload []byte,
	selectedpath snet.Path,
) ([]byte, error) {
	log.Printf("[BUILD-SCION] enter srcIA=%d-%d dstIA=%d-%d srcHost=%s dstHost=%s flowID=%d trafficClass=%d nextHeader=%v l4Type=%T payloadLen=%d selectedPathType=%T",
		localISD,
		localASN,
		dstISD,
		dstASN,
		ipString(srcHost),
		ipString(dstHost),
		flowID,
		tc,
		nextHeader,
		l4layer,
		len(l4Payload),
		selectedpath,
	)
	//TODO: Handle TCP
	//	[ SCION header | L4 header (UDP/TCP) | application payload bytes ]

	dstIA, err := addr.IAFrom(addr.ISD(dstISD), addr.AS(dstASN))
	if err != nil {
		return nil, fmt.Errorf("invalid dst IA: %w", err)
	}
	srcIA := addr.MustIAFrom(addr.ISD(localISD), addr.AS(localASN))

	pkt := &slayers.SCION{
		Version:      slayers.SCIONVersion,
		TrafficClass: tc,
		FlowID:       flowID,
		NextHdr:      nextHeader,
		SrcIA:        srcIA,
		DstIA:        dstIA,
	}

	log.Printf("[TRANSLATE-EGRESS] SrcIA: %v", srcIA)
	log.Printf("[TRANSLATE-EGRESS] DstIA: %v", dstIA)

	// Convert net.IP to netip.Addr
	srcAddr, err := ipToNetip(srcHost)
	if err != nil {
		return nil, fmt.Errorf("convert srcHost: %w", err)
	} else {
		log.Printf("srcAddr %s", srcAddr)
		log.Printf("srcAddr %v", srcAddr)
		log.Printf("srcAddr %w", srcAddr)
	}

	dstAddr, err := ipToNetip(dstHost)
	if err != nil {
		return nil, fmt.Errorf("convert dstHost: %w", err)
	} else {
		log.Printf("dstAddr %s", dstAddr)
		log.Printf("dstAddr %v", dstAddr)
		log.Printf("dstAddr %w", dstAddr)
	}

	pkt.SetSrcAddr(addr.HostIP(srcAddr))
	pkt.SetDstAddr(addr.HostIP(dstAddr))

	log.Printf("[BUILD-SCION] host addresses set srcHost=%s dstHost=%s srcAddrType=%v dstAddrType=%v",
		ipString(srcHost),
		ipString(dstHost),
		pkt.SrcAddrType,
		pkt.DstAddrType,
	)

	dp := selectedpath.Dataplane()
	log.Printf("[TRANSLATE-EGRESS] Dataplane: %v", dp)
	if dp != nil {
		log.Printf("[TRANSLATE-EGRESS] Calling dp.SetPath()")
		if err := dp.SetPath(pkt); err != nil {
			log.Printf("[TRANSLATE-EGRESS] dp.SetPath error: %v", err)
			return nil, fmt.Errorf("set dataplane selectedpath: %w", err)
		}
		log.Printf("[TRANSLATE-EGRESS] dp.SetPath() succeeded")
	} else {
		log.Printf("[TRANSLATE-EGRESS] No dataplane, using empty path")
		pkt.PathType = empty.PathType
		pkt.Path = empty.Path{}
	}
	log.Printf("[TRANSLATE-EGRESS] Path PathType: %v", pkt.PathType)

	//pkt.RawSrcAddr = srcHost
	//pkt.RawDstAddr = dstHost
	//Need addr.Host to set address of pkt otherwissssssse it does not work

	//pkt.Payload = l4Payload
	//pkt.PayloadLen = uint16(len(l4Payload))

	if pkt.PathType != 0 && pkt.Path == nil {
		return nil, fmt.Errorf("SCION header has PathType=%v but Path=nil", pkt.PathType)
	}

	buf := gopacket.NewSerializeBuffer()

	// --- set L4 checksum using SCION as the network layer ---
	switch l := l4layer.(type) {
	case *slayers.UDP:
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		//gopacket can not compute checksum for scion packets

		l.SetNetworkLayerForChecksum(pkt)

		if err := gopacket.SerializeLayers(buf, opts,
			pkt,
			l4layer,
			gopacket.Payload(l4Payload),
		); err != nil {
			return nil, fmt.Errorf("failed to serialize SCION+L4: %w", err)
		}
		log.Printf("[BUILD-SCION] serialized SCION/UDP success len=%d srcIA=%s dstIA=%s payloadLen=%d",
			len(buf.Bytes()),
			srcIA,
			dstIA,
			len(l4Payload),
		)

	case *layers.TCP:

		//TODO: Checksum Compute like slayers.UDP check slayers
		//Optional: Fork Proto, implement directly. <- Preferred (Replace in go.sum) https://go.dev/ref/mod#go-mod-file-replace

		// 1) Header ohne Checksum serialisieren
		l.Checksum = 0
		hdrbuf := gopacket.NewSerializeBuffer()

		if err := l.SerializeTo(hdrbuf, gopacket.SerializeOptions{
			FixLengths:       true,  // setzt DataOffset korrekt
			ComputeChecksums: false, // wir rechnen selbst
		}); err != nil {
			return nil, fmt.Errorf("serialize TCP for checksum: %w", err)
		}
		tcpBytes := hdrbuf.Bytes()

		upperLen := uint16(len(tcpBytes) + len(l4Payload)) // TCP-Header + Payload

		pseudo, err := buildSCIONPseudoHeader(
			srcIA, dstIA,
			srcHost, dstHost,
			upperLen,
			nextHeader, // = slayers.L4TCP
		)
		if err != nil {
			return nil, fmt.Errorf("build SCION TCP pseudo header: %w", err)
		}

		bufForCksum := make([]byte, 0, len(pseudo)+len(tcpBytes)+len(l4Payload))
		bufForCksum = append(bufForCksum, pseudo...)
		bufForCksum = append(bufForCksum, tcpBytes...)
		bufForCksum = append(bufForCksum, l4Payload...)

		l.Checksum = checksum16(bufForCksum)

		log.Printf("[BUILD-SCION] TCP checksum computed checksum=0x%04x tcpHeaderLen=%d payloadLen=%d pseudoLen=%d upperLen=%d",
			l.Checksum,
			len(tcpBytes),
			len(l4Payload),
			len(pseudo),
			upperLen,
		)

		// 4) NOW build the actual SCION packet: [SCION header | TCP | payload]
		//scionBuf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(
			buf,
			gopacket.SerializeOptions{
				FixLengths:       true,  // sets HdrLen, PayloadLen
				ComputeChecksums: false, // we already set TCP checksum
			},
			pkt,
			l,
			gopacket.Payload(l4Payload),
		); err != nil {
			return nil, fmt.Errorf("serialize SCION/TCP: %w", err)
		}
		log.Printf("[BUILD-SCION] serialized SCION/TCP success len=%d srcIA=%s dstIA=%s payloadLen=%d",
			len(buf.Bytes()),
			srcIA,
			dstIA,
			len(l4Payload),
		)

	case *slayers.SCMP:
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: false,
		}

		l.SetNetworkLayerForChecksum(pkt)

		if err := gopacket.SerializeLayers(buf, opts,
			pkt,
			l4layer,
			gopacket.Payload(l4Payload),
		); err != nil {
			return nil, fmt.Errorf("failed to serialize SCION+SCMP: %w", err)
		}
		log.Printf("[BUILD-SCION] serialized SCION/SCMP success len=%d srcIA=%s dstIA=%s payloadLen=%d",
			len(buf.Bytes()),
			srcIA,
			dstIA,
			len(l4Payload),
		)

	default:
		// If you ever pass something else, checksums won’t be computed correctly.
		return nil, fmt.Errorf("unsupported L4 layer type %T; expected *slayers.UDP or *layers.TCP", l4layer)
	}

	//SetNetworkLayerForChecmsum only accepts *layers.IPv4 or IPv6? Does not work with *slyers.SCION for pkt.

	//---------------------------------------------------------------------------------------------------------

	out := buf.Bytes()
	log.Printf("[BUILD-SCION] exit success scionLen=%d srcIA=%s dstIA=%s pathType=%v nextHeader=%v",
		len(out),
		srcIA,
		dstIA,
		pkt.PathType,
		nextHeader,
	)
	return out, nil
}

// -------------------------------------------- CHECKSUM ----------------------------------------
//https://datatracker.ietf.org/doc/html/rfc1624

// checksum16 computes the standard 16-bit ones-complement checksum
// used for IP/UDP/TCP.
func checksum16(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildSCIONPseudoHeader builds the SCION pseudo header for IPv4 and IPv6
// host addresses, according to the spec:
//
//	DstISD(2) | DstAS(4) | SrcISD(2) | SrcAS(4) |
//	DstHost | SrcHost | UpperLen(4) | zero(3) | NextHdr(1)
func buildSCIONPseudoHeader(
	srcIA, dstIA addr.IA,
	srcHost, dstHost net.IP,
	upperLen uint16,
	nextHdr slayers.L4ProtocolType,
) ([]byte, error) {

	src4 := srcHost.To4()
	dst4 := dstHost.To4()

	var hostPart []byte
	switch {
	case src4 != nil && dst4 != nil:
		// IPv4 hosts: 4+4 bytes
		hostPart = make([]byte, 8)
		copy(hostPart[0:4], dst4)
		copy(hostPart[4:8], src4)
	default:
		// IPv6 hosts: use full 16-byte addresses
		src16 := srcHost.To16()
		dst16 := dstHost.To16()
		if src16 == nil || dst16 == nil {
			return nil, fmt.Errorf("buildSCIONUDPPseudoHeader: invalid host IPs")
		}
		hostPart = make([]byte, 32)
		copy(hostPart[0:16], dst16)
		copy(hostPart[16:32], src16)
	}

	/// base: dstIA(8) + srcIA(8) + hostPart + upperLen(4) + zero(3)/nextHdr(1)
	baseLen := 8 + 8 + len(hostPart) + 4 + 4
	b := make([]byte, baseLen)

	off := 0

	binary.BigEndian.PutUint16(b[off:], uint16(dstIA.ISD()))
	off += 2
	putAS48(b[off:off+6], dstIA.AS())
	off += 6

	binary.BigEndian.PutUint16(b[off:], uint16(srcIA.ISD()))
	off += 2
	putAS48(b[off:off+6], srcIA.AS())
	off += 6

	// Host addresses
	copy(b[off:], hostPart)
	off += len(hostPart)

	// Upper-layer length (UDP header + payload)
	binary.BigEndian.PutUint32(b[off:], uint32(upperLen))
	off += 4

	// zero(3) | NextHdr(1)
	b[off] = 0
	b[off+1] = 0
	b[off+2] = 0
	b[off+3] = byte(nextHdr)

	return b, nil
}

func computeMSS(ipMTU int) uint16 {
	return uint16(ipMTU - 40 - 20) // IPv6(40) + TCP(20)
}

func putAS48(b []byte, as addr.AS) {
	v := uint64(as)
	b[0] = byte(v >> 40)
	b[1] = byte(v >> 32)
	b[2] = byte(v >> 24)
	b[3] = byte(v >> 16)
	b[4] = byte(v >> 8)
	b[5] = byte(v)
}
