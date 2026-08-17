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
	"golang.zx2c4.com/wireguard/scionlog"
	"golang.zx2c4.com/wireguard/translator/addr_translation"
	"golang.zx2c4.com/wireguard/translator/pathpolicy"
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
	return addr_translation.FormatSCIONIPv6(ip)
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

// WGSrcIPv6 returns the local IPv6 address for the tunnel interface.
// Priority: configured address (Android) > interface lookup (Linux).
func (t *Translator) WGSrcIPv6() (net.IP, error) {
	// Priority 1: Use explicitly configured address (Android path).
	if t.configuredIPv6 != nil {
		ip := append(net.IP(nil), t.configuredIPv6...)
		t.log.Infof(scionlog.ComponentPath, "[WG-ADDR] using configured WG IPv6 sourceMode=android-config ip=%s", ip)
		return ip, nil
	}

	// Priority 2: Fall back to interface lookup (Linux path).
	if t.ifaceName == "" {
		return nil, fmt.Errorf("no IPv6 source: configuredIPv6=<none> interfaceName=empty")
	}

	ip, err := IPv6OfInterface(t.ifaceName)
	if err != nil {
		return nil, fmt.Errorf("no IPv6 source: configuredIPv6=<none> interfaceLookup=failed iface=%s err=%w", t.ifaceName, err)
	}

	t.log.Infof(scionlog.ComponentPath, "[WG-ADDR] interface IPv6 lookup success iface=%s ip=%s", t.ifaceName, ip)
	return ip, nil
}

func (t *Translator) WGSrcIPv4() (net.IP, error) {
	t.wgSrcIPMu.RLock()
	if t.wgSrcIP != nil && t.wgSrcIP.To4() != nil {
		ip := append(net.IP(nil), t.wgSrcIP...)
		t.wgSrcIPMu.RUnlock()

		t.log.Infof(scionlog.ComponentPath, "[WG-ADDR] using cached WG IPv4 iface=%s ip=%s", t.ifaceName, ip)
		return ip, nil
	}
	t.wgSrcIPMu.RUnlock()

	t.wgSrcIPMu.Lock()
	defer t.wgSrcIPMu.Unlock()

	// Double-check, falls eine andere Goroutine die IP inzwischen gesetzt hat.
	if t.wgSrcIP != nil && t.wgSrcIP.To4() != nil {
		ip := append(net.IP(nil), t.wgSrcIP...)
		t.log.Infof(scionlog.ComponentPath, "[WG-ADDR] using cached WG IPv4 after lock iface=%s ip=%s", t.ifaceName, ip)
		return ip, nil
	}

	// Priority 1: Use explicitly configured address (Android path).
	if t.configuredIPv4 != nil {
		ip := append(net.IP(nil), t.configuredIPv4...)
		t.wgSrcIP = append(net.IP(nil), ip...)
		t.log.Infof(scionlog.ComponentPath, "[WG-ADDR] using configured WG IPv4 sourceMode=android-config ip=%s", ip)
		return ip, nil
	}

	// Priority 2: Fall back to interface lookup (Linux path).
	if t.ifaceName == "" {
		return nil, fmt.Errorf("SCION-EGRESS-ERROR reason=missing_outer_ipv4_source configuredIPv4=<none> interfaceName=empty")
	}

	ip, err := IPv4OfInterface(t.ifaceName)
	if err != nil {
		t.log.Infof(scionlog.ComponentPath, "[WG-ADDR] interface lookup failed iface=%s err=%v", t.ifaceName, err)
		return nil, fmt.Errorf("SCION-EGRESS-ERROR reason=missing_outer_ipv4_source configuredIPv4=<none> interfaceLookup=failed iface=%s err=%w", t.ifaceName, err)
	}

	t.wgSrcIP = append(net.IP(nil), ip...)

	t.log.Infof(scionlog.ComponentPath, "[WG-ADDR] lazy WG IPv4 lookup success iface=%s ip=%s", t.ifaceName, ip)

	return append(net.IP(nil), ip...), nil
}

type MappedDestination struct {
	SrcIA addr.IA
	DstIA addr.IA
	Host  netip.Addr
}

func (t *Translator) MappedDestinationFor(dstIP net.IP) (MappedDestination, error) {
	t.log.Infof(scionlog.ComponentPath, "[IA-MAP] enter dstIP=%s localIA=%s", ipString(dstIP), t.localIA)

	if !IsSCIONMapped(dstIP) {
		t.log.Infof(scionlog.ComponentPath, "[IA-MAP] not SCION-mapped dstIP=%s", ipString(dstIP))
		return MappedDestination{}, fmt.Errorf("dst IP is not SCION-mapped: %s", dstIP)
	}

	isd, asn, localPrefix, subnet, host, hostIsIPv4, err := UnmapIPv6(dstIP, 8)
	if err != nil {
		t.log.Infof(scionlog.ComponentPath, "[IA-MAP] UnmapIPv6 failed dstIP=%s err=%v", ipString(dstIP), err)
		return MappedDestination{}, fmt.Errorf("unmap IPv6 failed: %w", err)
	}

	dstIA := addr.MustIAFrom(addr.ISD(isd), addr.AS(asn))

	srcIA := t.localIA
	if srcIA == 0 {
		t.log.Infof(scionlog.ComponentPath, "[IA-MAP] localIA not configured dstIP=%s dstIA=%s", ipString(dstIP), dstIA)
		return MappedDestination{}, fmt.Errorf("localIA not configured")
	}

	hostIP, hostErr := ipToNetip(host)
	if hostErr != nil {
		t.log.Infof(scionlog.ComponentPath, "[IA-MAP] ipToNetip failed dstIP=%s host=%s err=%v", ipString(dstIP), ipString(host), hostErr)
		return MappedDestination{}, fmt.Errorf("convert host IP: %w", hostErr)
	}

	t.log.Infof(scionlog.ComponentPath, "[IA-MAP] success dstIP=%s srcIA=%s dstIA=%s isd=%d asn=%d localPrefix=%d subnet=%d host=%s hostIP=%s hostIsIPv4=%v",
		ipString(dstIP),
		srcIA,
		dstIA,
		isd,
		asn,
		localPrefix,
		subnet,
		ipString(host),
		hostIP,
		hostIsIPv4,
	)

	return MappedDestination{
		SrcIA: srcIA,
		DstIA: dstIA,
		Host:  hostIP,
	}, nil
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
	cache        PathPool
	localIA      addr.IA
	brAddr       *net.UDPAddr // BR address for same-AS fallback
	policyEngine *pathpolicy.Engine

	ifaceName string

	// Explicitly configured local addresses (Android path).
	// When set, these bypass net.InterfaceByName which is unavailable on Android.
	configuredIPv4 net.IP
	configuredIPv6 net.IP

	wgSrcIPMu sync.RWMutex
	wgSrcIP   net.IP

	dispatchedPorts DispatchPortRange

	log *scionlog.Logger
}

func (t *Translator) SetDispatchedPorts(r DispatchPortRange) {
	t.dispatchedPorts = r
}

func (t *Translator) LocalIA() addr.IA {
	return t.localIA
}

func (t *Translator) BRAddr() *net.UDPAddr {
	return t.brAddr
}

func (t *Translator) DispatchedPorts() DispatchPortRange {
	return t.dispatchedPorts
}

// SetConfiguredIPv4 sets the local IPv4 address for outer encapsulation.
// Used on Android where net.InterfaceByName is unavailable.
func (t *Translator) SetConfiguredIPv4(addr netip.Addr) {
	a4 := addr.As4()
	t.configuredIPv4 = net.IP(a4[:])
}

// SetConfiguredIPv6 sets the local IPv6 address for the tunnel interface.
// Used on Android where net.InterfaceByName is unavailable.
func (t *Translator) SetConfiguredIPv6(addr netip.Addr) {
	a16 := addr.As16()
	t.configuredIPv6 = net.IP(a16[:])
}

func NewTranslator(cache PathPool, localIA addr.IA, brAddr *net.UDPAddr, ifaceName string, log *scionlog.Logger) *Translator {
	if log == nil {
		log = scionlog.NewLogger(
			func(string, ...any) {},
			func(string, ...any) {},
		)
	}

	return &Translator{
		cache:     cache,
		localIA:   localIA,
		brAddr:    brAddr,
		ifaceName: ifaceName,
		log:       log,
	}
}

// SetPolicyEngine sets the path policy engine for policy-based path selection.
// If nil, the translator falls back to first-valid path selection.
func (t *Translator) SetPolicyEngine(engine *pathpolicy.Engine) {
	t.policyEngine = engine
	if engine != nil {
		log.Printf("[TRANSLATE] path policy engine configured")
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
	t.log.Infof(scionlog.ComponentPath, "[READ-OUTBOUND] enter pkt=%s srcIP=%s dstIP=%s hostPort=%d isIPv6=%v localIA=%s brAddr=%s",
		packetSummary(pkt),
		ipString(srcIP),
		ipString(dstIP),
		hostPort,
		isIPv6,
		t.localIA,
		udpAddrString(t.brAddr),
	)

	if !isIPv6 {
		t.log.Infof(scionlog.ComponentPath, "[READ-OUTBOUND] bypass normal IPv4 packet dstIP=%s pktLen=%d",
			ipString(dstIP),
			len(pkt),
		)
		return pkt, nil
	}

	if !IsSCIONMapped(dstIP) {
		t.log.Infof(scionlog.ComponentPath, "[READ-OUTBOUND] bypass: dstIP is not SCION-mapped dstIP=%s pktLen=%d",
			ipString(dstIP),
			len(pkt),
		)
		return pkt, nil
	}

	t.log.Infof(scionlog.ComponentPath, "[READ-OUTBOUND] SCION-mapped destination detected dstIP=%s", ipString(dstIP))

	t.log.Infof(scionlog.ComponentPath, "HIER mussen wir eigentlich schon als srcIP die IP des WG Interface ubergeben.")
	newpkt, nextHop, err := t.TranslateEgress(pkt, srcIP, hostPort, nil)
	if err != nil {
		t.log.Infof(scionlog.ComponentPath, "[READ-OUTBOUND] TranslateEgress failed srcIP=%s dstIP=%s hostPort=%d err=%v",
			ipString(srcIP),
			ipString(dstIP),
			hostPort,
			err,
		)
		return pkt, fmt.Errorf("TranslateEgress failed: %w", err)
	}

	t.log.Infof(scionlog.ComponentPath, "[READ-OUTBOUND] translated successfully originalLen=%d translatedLen=%d nextHop=%s",
		len(pkt),
		len(newpkt),
		udpAddrString(nextHop),
	)

	return newpkt, nil
}

func (t *Translator) getPathFromCache(srcIA, dstIA addr.IA) (path.Path, error) {
	t.log.Infof(scionlog.ComponentPath, "[PATHLOOKUP] enter srcIA=%s dstIA=%s", srcIA, dstIA)

	if srcIA == dstIA {
		t.log.Infof(scionlog.ComponentPath, "[PATHLOOKUP] same-AS traffic detected srcIA=%s dstIA=%s using empty path", srcIA, dstIA)
		return path.Path{}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	t.log.Infof(scionlog.ComponentPath, "[PATHLOOKUP] cache.Get start srcIA=%s dstIA=%s timeout=2s", srcIA, dstIA)

	CachedPaths, err := t.cache.Get(ctx, srcIA, dstIA)
	elapsed := time.Since(start)

	if err != nil {
		t.log.Infof(scionlog.ComponentPath, "[PATHLOOKUP] cache.Get failed srcIA=%s dstIA=%s elapsed=%s err=%v",
			srcIA,
			dstIA,
			elapsed,
			err,
		)
		return path.Path{}, fmt.Errorf("path cache error for %s -> %s: %w", srcIA, dstIA, err)
	}

	t.log.Infof(scionlog.ComponentPath, "[PATHLOOKUP] cache.Get returned srcIA=%s dstIA=%s elapsed=%s count=%d",
		srcIA,
		dstIA,
		elapsed,
		len(CachedPaths),
	)

	if len(CachedPaths) == 0 {
		t.log.Infof(scionlog.ComponentPath, "[PATHLOOKUP] no paths available srcIA=%s dstIA=%s", srcIA, dstIA)
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

		t.log.Infof(scionlog.ComponentPath, "[PATHPOOL] candidate path[%d]: src=%s dst=%s fp=%s nextHop=%v expiry=%s mtu=%d interfaces=%v",
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
	//Use policy engine if available, otherwise select first path.
	var selectedcachedpath pathpool.CachedPath
	if t.policyEngine != nil {
		selectedcachedpath = t.selectPathWithPolicy(CachedPaths, srcIA, dstIA)
		log.Print("[PATHPOOL] using path policy")
	} else {
		selectedcachedpath = selectPath(CachedPaths)
		log.Print("[PATHPOOL] NOT using path policy")
	}

	meta := selectedcachedpath.Path.Metadata()

	var expiry time.Time
	var mtu uint16
	var interfaces any

	if meta != nil {
		expiry = meta.Expiry
		mtu = meta.MTU
		interfaces = meta.Interfaces
	}

	t.log.Infof(scionlog.ComponentPath, "[PATHPOOL] selection strategy=first-valid src=%s dst=%s selectedFingerprint=%s nextHop=%v expiry=%s mtu=%d interfaces=%v available=%d",
		srcIA,
		dstIA,
		selectedcachedpath.Fingerprint,
		selectedcachedpath.NextHop,
		expiry.Format(time.RFC3339Nano),
		mtu,
		interfaces,
		len(CachedPaths),
	)

	t.log.Infof(scionlog.ComponentPath, "[PATHPOOL] selected cached path: srcIA=%s dstIA=%s fp=%s nextHop=%v",
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

// selectPathWithPolicy uses the policy engine to filter and sort paths.
// It constructs a minimal PacketInfo from available context. Full packet-level
// matching (protocol, ports, DSCP) happens in selectPathsWithFullInfo which
// is called from TranslateEgress where the parsed packet is available.
func (t *Translator) selectPathWithPolicy(paths []pathpool.CachedPath, srcIA, dstIA addr.IA) pathpool.CachedPath {
	info := pathpolicy.PacketInfo{
		SrcIA: srcIA,
		DstIA: dstIA,
	}

	selected := t.policyEngine.SelectPaths(info, paths)
	if len(selected) > 0 {
		return selected[0]
	}

	// Fallback: if policy yields nothing, use first available.
	log.Printf("[PATHPOLICY] policy yielded 0 paths, falling back to first-valid")
	return paths[0]
}

// SelectPathsWithFullInfo applies the policy engine with full packet metadata
// for fine-grained matcher evaluation. Called from TranslateEgress after
// the packet has been parsed so protocol, ports, and DSCP are known.
func (t *Translator) SelectPathsWithFullInfo(paths []pathpool.CachedPath, info pathpolicy.PacketInfo) []pathpool.CachedPath {
	if t.policyEngine == nil {
		return paths
	}
	return t.policyEngine.SelectPaths(info, paths)
}

type GetPathFunc func(srcIA, dstIA addr.IA) (path.Path, error)

// IPv6 -> SCION
// returns SCION packet bytes and the UDP next-hop to send to if successful
//
// hostPort is kept for call-site compatibility but no longer drives any port
// selection:
//
//   - The outer UDP source port of TCP/UDP data flows is the inner L4 source
//     port, so the peer can reply to the client port.
//   - The outer UDP source port of SCMP/ICMPv6 traffic (which carries no L4
//     ports) is the well-known SCION end-host/dispatcher port
//     (DefaultSCIONEndhostPort).
//   - The same-AS (empty path) outer UDP destination port is the inner L4
//     destination port for TCP/UDP and DefaultSCIONEndhostPort for SCMP.
func (t *Translator) TranslateEgress(pktData []byte, hostIP net.IP, hostPort int, getPath GetPathFunc) ([]byte, *net.UDPAddr, error) {
	if len(pktData) < 40 {
		return nil, nil, errors.New("packet too short for IPv6")
	}

	packet := gopacket.NewPacket(pktData, layers.LayerTypeIPv6, gopacket.Default)
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer == nil {
		return nil, nil, errors.New("not an IPv6 packet")
	}
	ip6 := ip6Layer.(*layers.IPv6)

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

	// Outer UDP source port. Defaults to the well-known SCION end-host/
	// dispatcher port, which is used for SCMP/ICMPv6 traffic that carries no
	// L4 ports. For TCP/UDP data flows it is overridden below with the inner
	// L4 source port so the receiving side sees a consistent (outer UDP, inner
	// TCP/UDP) port pair.
	outerSrcPort := DefaultSCIONEndhostPort

	if !IsSCIONMapped(ip6.DstIP) {
		return nil, nil, errors.New("dst not in SCION-mapped network")
	}

	isd, asn, _, _, host, hostIsIPv4, err := UnmapIPv6(ip6.DstIP, 8) // subnetBits = 8

	if err != nil {
		return nil, nil, fmt.Errorf("unmap IPv6 failed: %w", err)
	}

	srcHost := hostIP

	if ip4, err := t.WGSrcIPv4(); err == nil {
		srcHost = ip4
	}

	dstIA := addr.IA(addr.MustIAFrom(addr.ISD(isd), addr.AS(asn)))
	srcIA := t.localIA
	if srcIA == 0 {
		return nil, nil, fmt.Errorf("localIA not configured (t.localIA=%v)", t.localIA)
	}

	var selectedPath path.Path
	if getPath != nil {
		selectedPath, err = getPath(srcIA, dstIA)
	} else {
		selectedPath, err = t.getPathFromCache(srcIA, dstIA)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("path unavailable for dst IA: %w", err)
	}

	nextHop := selectedPath.UnderlayNextHop()

	// TODO: NEEDS CHECKING
	var dstHost net.IP
	if hostIsIPv4 {
		dstHost = host.To4()
		if dstHost == nil {
			return nil, nil, fmt.Errorf("decoded IPv4 host is invalid: %s", host)
		}
	} else {
		// SCION-mapped IPv6 with an interface-style host (no embedded IPv4).
		// The reference fixtures carry the full SCION-mapped IPv6 as the T16Ip
		// host, not the bare low-64 interface identifier, so keep the original
		// destination address instead of the unmapped host.
		dstHost = ip6.DstIP.To16()
		if dstHost == nil {
			return nil, nil, fmt.Errorf("decoded IPv6/interface host is invalid: %s", host)
		}
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
		outerSrcPort = uint16(udp.SrcPort)

		// --- FIX: Extract correct payload ---
		var l4Payload []byte
		if app := packet.ApplicationLayer(); app != nil {
			l4Payload = append([]byte(nil), app.Payload()...) // copy
		}

		scionBytes, err = BuildSCIONPacket(
			localISD, localASN, dstISD, dstASN,
			srcHost, dstHost,
			flowID, tc,
			l4nextHeader, innerUDP, l4Payload,
			selectedPath,
			t.log,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("build scion packet failed: %w", err)
		}

	case layers.IPProtocolTCP:
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			return nil, nil, errors.New("tcp layer missing")
		}

		tcp := tcpLayer.(*layers.TCP)
		l4nextHeader = slayers.L4TCP

		//SrcPort = int(tcp.SrcPort)
		DstPort = int(tcp.DstPort)

		innerDstPort = uint16(tcp.DstPort)
		hasInnerDstPort = true
		outerSrcPort = uint16(tcp.SrcPort)

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
				opt.OptionData[0] = byte(newMSS >> 8)
				opt.OptionData[1] = byte(newMSS & 0xff)
				innerTCP.Options[i] = opt
			}
		}

		var l4Payload []byte
		if app := packet.ApplicationLayer(); app != nil {
			l4Payload = append([]byte(nil), app.Payload()...) // copy
		}

		scionBytes, err = BuildSCIONPacket(localISD, localASN, dstISD, dstASN, srcHost, dstHost, flowID, tc, l4nextHeader, innerTCP, l4Payload, selectedPath, t.log)
		if err != nil {
			return nil, nil, fmt.Errorf("build scion packet failed: %w", err)
		}

	case layers.IPProtocolICMPv6: // 58
		icmpLayer := packet.Layer(layers.LayerTypeICMPv6)
		if icmpLayer == nil {
			return nil, nil, errors.New("ICMPv6 layer missing")
		}
		icmp := icmpLayer.(*layers.ICMPv6)
		l4nextHeader = slayers.L4SCMP

		scmpTypeCode := translateICMPv6ToSCMPTypeCode(icmp.TypeCode, t.log)

		scmp := &slayers.SCMP{
			TypeCode: scmpTypeCode,
		}

		// The ICMPv6 payload (everything after the 4-byte type/code/checksum)
		// is the echo info block + data for Echo messages and type-specific
		// data otherwise. For Echo messages we build the SCMPEcho info block
		// and carry the original ICMPv6 identifier inside the data block; for
		// all other ICMPv6 types the payload is passed through unchanged.
		scmpPayload := append([]byte(nil), icmp.Payload...)
		if isICMPv6Echo(icmp.TypeCode) {
			scmpPayload = buildSCMPEchoPayload(scmpTypeCode.Type(), icmp.Payload, t.log)
		}

		scionBytes, err = BuildSCIONPacket(
			localISD, localASN, dstISD, dstASN,
			srcHost, dstHost,
			flowID, tc,
			l4nextHeader, scmp, scmpPayload,
			selectedPath,
			t.log,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("build scion packet failed: %w", err)
		}

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
			port := chooseSameASDispatchPort(innerDstPort, hasInnerDstPort)

			nextHop = &net.UDPAddr{
				IP:   dstHost,
				Port: int(port),
			}

			t.log.Infof(
				scionlog.ComponentPath, "[TRANSLATE-EGRESS] same-AS empty path, using direct dst host nextHop=%s selectedPort=%d innerDstPort=%d hasInnerDstPort=%v outerSrcPort=%d",
				nextHop.String(),
				port,
				innerDstPort,
				hasInnerDstPort,
				outerSrcPort,
			)
		} else {
			return nil, nil, fmt.Errorf("no nextHop for non-local path srcIA=%s dstIA=%s", srcIA, dstIA)
		}
	}
	// hostIsIPv4 - check nextHop's address family since that's what we're sending to
	// For IPv4 underlay, we need an IPv4 source (underlay IP), not the TUN IP
	if nextHop.IP.To4() != nil {
		// Use underlay IPv4 address as source for the outer IPv4 header.
		// Priority: configured IPv4 (Android) > interface lookup (Linux).
		srcIP := srcHost
		if srcHost.To4() == nil {
			ipv4, err := t.WGSrcIPv4()
			if err != nil {
				return nil, nil, fmt.Errorf("[SCION-EGRESS-ERROR] reason=missing_outer_ipv4_source %w", err)
			}
			srcIP = ipv4
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
			SrcPort: layers.UDPPort(outerSrcPort),
			DstPort: layers.UDPPort(nextHop.Port),
		}
		udp.SetNetworkLayerForChecksum(ip4)
		if err := gopacket.SerializeLayers(buf, opts,
			ip4,
			udp,
			gopacket.Payload(scionBytes),
		); err != nil {
			return nil, nil, fmt.Errorf("failed to serialize IPv4/UDP+SCION: %w", err)
		}
	} else {
		// -------- IPv6 underlay --------
		// Use configured or interface IPv6 address as source.
		srcIP, err := t.WGSrcIPv6()
		if err != nil {
			return nil, nil, fmt.Errorf("[SCION-EGRESS-ERROR] reason=missing_outer_ipv6_source %w", err)
		}

		ip6Under := &layers.IPv6{
			Version:      6,
			TrafficClass: tc,
			FlowLabel:    ip6.FlowLabel,
			HopLimit:     64,
			NextHeader:   layers.IPProtocolUDP,
			SrcIP:        srcIP,
			DstIP:        nextHop.IP,
		}

		// Outer UDP source port: derived from the inner L4 source port for
		// TCP/UDP data flows; falls back to the SCION endhost/control port
		// (hostPort) for SCMP which carries no L4 ports.
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(outerSrcPort),
			DstPort: layers.UDPPort(nextHop.Port),
		}
		udp.SetNetworkLayerForChecksum(ip6Under)
		if err := gopacket.SerializeLayers(buf, opts,
			ip6Under,
			udp,
			gopacket.Payload(scionBytes),
		); err != nil {
			return nil, nil, fmt.Errorf("failed to serialize IPv6/UDP+SCION: %w", err)
		}
	}

	//Outer = [ IPv4 header | UDP header | SCION header | SCION L4 payload ]
	//We need TCP Out the same
	outer := buf.Bytes()

	return outer, nextHop, nil

}

// SCION -> IPv6
func (t *Translator) TranslateIngress(pktData []byte, tunIP net.IP) ([]byte, error) {
	if len(pktData) == 0 {
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

	t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] outer UDP srcPort=%d dstPort=%d payloadLen=%d",
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
		t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] SCION decode failed or unsupported sublayer srcPort=%d dstPort=%d payloadLen=%d decoded=%v err=%v",
			udpOuter.SrcPort,
			udpOuter.DstPort,
			len(scionPayload),
			decoded,
			err,
		)
		return pktData, nil
	}

	t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] SCION decoded srcIA=%s dstIA=%s nextHdr=%v",
		scn.SrcIA,
		scn.DstIA,
		scn.NextHdr,
	)

	var l4Layer gopacket.SerializableLayer
	var l4Payload []byte

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
			// For SCMP Echo, the bytes after the SCMP header are the echo
			// info block: identifier + sequence + echo data. It maps 1:1 to
			// the ICMPv6 payload (identifier + sequence + data).
			scmpPayload := append([]byte(nil), scmp.LayerPayload()...)

			// Fallback, in case gopacket put something into pld.
			if len(scmpPayload) == 0 && len(pld) > 0 {
				scmpPayload = append([]byte(nil), []byte(pld)...)
			}

			t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] SCMP typeCode=%v payloadLen=%d",
				scmp.TypeCode,
				len(scmpPayload),
			)

			icmpTypeCode := translateSCMPTypeCodeToICMPv6(scmp.TypeCode, t.log)

			// SCMP Echo Replies carry the original ICMPv6 identifier stashed
			// by the egress translation inside the data block; restore it so
			// the originating ping matches its reply. Echo Requests are left
			// as-is: their identifier is the sender's dispatcher/underlay port.
			if scmp.TypeCode.Type() == slayers.SCMPTypeEchoReply {
				scmpPayload = restoreICMPv6EchoID(scmpPayload, t.log)
			}

			icmp := &layers.ICMPv6{
				TypeCode: icmpTypeCode,
			}

			l4Layer = icmp
			l4Payload = scmpPayload
		case layers.LayerTypeTCP:
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

		t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] fallback TCP decode rawLen=%d", len(raw))

		if err := tcp.DecodeFromBytes(raw, gopacket.NilDecodeFeedback); err != nil {
			return nil, fmt.Errorf("failed to decode fallback inner TCP: %w", err)
		}

		l4Layer = &tcp
		l4Payload = append([]byte(nil), tcp.Payload...)
	}

	// ---------------------------- Map SCION hosts -> IP -----------------------
	// The reconstructed application packet mirrors the SCION packet's hosts
	// transparently: src = mapped SCION src host, dst = mapped SCION dst host.
	// Both are canonical SCION-mapped IPv6 addresses (Scitra-conformant); there
	// is no family branch and no islocal-dependent address handling here.
	var dst, src net.IP

	mappedSrc, err := mapSCIONHostToIPv6(scn.SrcIA, scn.SrcAddrType, scn.RawSrcAddr)
	if err != nil {
		return nil, fmt.Errorf("map SCION src host to IPv6 failed: %w", err)
	}
	src = mappedSrc

	mappedDst, err := mapSCIONHostToIPv6(scn.DstIA, scn.DstAddrType, scn.RawDstAddr)
	if err != nil {
		return nil, fmt.Errorf("map SCION dst host to IPv6 failed: %w", err)
	}
	dst = mappedDst

	t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] reconstructed IPv6 addresses src=%s dst=%s",
		ipString(src),
		ipString(dst),
	)

	// ---- Build IP Packet ----

	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Return nil if not IPv4 Adr
	dst4 := dst.To4()
	src4 := src.To4()

	// OUTDATED: This IPv4 rebuild branch is no longer reachable. The address
	// rule above always reconstructs an IPv6 packet (Scitra-conformant), so src
	// and dst are never IPv4 and dst4/src4 are always nil. It is kept for
	// review/rollback context only and must NOT be used as an active path.
	//If both Src and Dst are IPv4, build IPv4 Packet
	if dst4 != nil && src4 != nil {

		t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] rebuilding inner IPv4 packet src=%s dst=%s l4Type=%T payloadLen=%d",
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

			t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] serializing IPv4/UDP src=%s dst=%s srcPort=%d dstPort=%d payloadLen=%d",
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
			t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] IPv4/UDP serialization success len=%d", len(out))
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

			t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] serializing IPv4/TCP src=%s dst=%s srcPort=%d dstPort=%d seq=%d ack=%d SYN=%v ACK=%v FIN=%v RST=%v PSH=%v window=%d options=%d payloadLen=%d",
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
			t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] IPv4/TCP serialization success len=%d", len(out))
			return out, nil

		}

	} else {

		t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] rebuilding inner IPv6 packet src=%s dst=%s l4Type=%T payloadLen=%d flowID=%d trafficClass=%d",
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

			t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] serializing IPv6/ICMPv6 src=%s dst=%s typeCode=%v payloadLen=%d",
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
			t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] IPv6/ICMPv6 serialization success len=%d", len(out))
			return out, nil
		}

	}
	out := buf.Bytes()
	if len(out) == 0 {
		return nil, fmt.Errorf("no packet serialized for l4Type=%T src=%s dst=%s", l4Layer, src, dst)
	}

	t.log.Infof(scionlog.ComponentPath, "[TRANSLATE-INGRESS] exit success rebuiltLen=%d src=%s dst=%s l4Type=%T",
		len(out),
		ipString(src),
		ipString(dst),
		l4Layer,
	)
	return out, nil

}

// mapSCIONHostToIPv6 returns the canonical SCION-mapped IPv6 address for a
// SCION host address as it is carried on the wire:
//   - T4Ip (IPv4 host)      -> fc<isd><asn>::ffff:IPv4 (via ScionToIP)
//   - T16Ip already mapped  -> the SCION-mapped IPv6 as-is
//   - T16Ip interface id    -> fc<isd><asn>::<low64> (via ScionToIP)
//
// This is the application-side source address used by TranslateIngress and is
// independent of whether the packet travelled a same-AS (empty) or inter-AS path.
func mapSCIONHostToIPv6(ia addr.IA, addrType slayers.AddrType, raw []byte) (net.IP, error) {
	asn := addr_translation.ASN{Value: uint64(ia.AS())}
	ip := net.IP(raw)

	switch addrType {
	case slayers.T4Ip:
		return addr_translation.ScionToIP(int(ia.ISD()), asn, 0, 0, ip, 8)
	case slayers.T16Ip:
		if IsSCIONMapped(ip) {
			return ip.To16(), nil
		}
		return addr_translation.ScionToIP(int(ia.ISD()), asn, 0, 0, ip, 8)
	default:
		return nil, errors.New("unsupported source host type")
	}
}

// translateICMPv6ToSCMPTypeCode maps ICMPv6 Type+Code to SCMP Type+Code.
func translateICMPv6ToSCMPTypeCode(icmp6TypeCode layers.ICMPv6TypeCode, log *scionlog.Logger) slayers.SCMPTypeCode {

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
			log.Infof(scionlog.ComponentPath, "[ICMP6->SCMP] warning: unsupported ICMPv6 DestinationUnreachable code=%d, fallback=NoRoute",
				icmp6TypeCode.Code())
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable, slayers.SCMPCodeNoRoute)
		}

	case layers.ICMPv6TypePacketTooBig:
		out = slayers.CreateSCMPTypeCode(slayers.SCMPTypePacketTooBig, 0)

	case layers.ICMPv6TypeTimeExceeded:
		log.Infof(scionlog.ComponentPath, "[ICMP6->SCMP] warning: ICMPv6 TimeExceeded has no direct SCMP equivalent, fallback=DestinationUnreachable(NoRoute)")
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
			log.Infof(scionlog.ComponentPath, "[ICMP6->SCMP] warning: unsupported ICMPv6 ParameterProblem code=%d, fallback=ErroneousHeaderField",
				icmp6TypeCode.Code())
			out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeParameterProblem, slayers.SCMPCodeErroneousHeaderField)
		}

	case layers.ICMPv6TypeEchoRequest:
		out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoRequest, 0)

	case layers.ICMPv6TypeEchoReply:
		out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeEchoReply, 0)

	default:
		log.Infof(scionlog.ComponentPath, "[ICMP6->SCMP] warning: unsupported ICMPv6 type=%d code=%d string=%s, fallback=DestinationUnreachable(NoRoute)",
			icmp6TypeCode.Type(),
			icmp6TypeCode.Code(),
			icmp6TypeCode.String(),
		)
		out = slayers.CreateSCMPTypeCode(slayers.SCMPTypeDestinationUnreachable, slayers.SCMPCodeNoRoute)
	}

	return out
}

// SCMPEcho data block offsets used to preserve the original ICMPv6 echo
// identifier on the SCION wire. SCION routers route SCMP informational
// requests to the default end-host port (30041) and route replies using the
// SCMPEcho identifier as the destination port, so the identifier field cannot
// carry the original ICMPv6 identifier. For echo data blocks of at least 18
// bytes the original identifier is stashed at bytes 16..17 of the data block
// and restored on ingress.
const (
	scmpEchoIdentifierStashOffset = 16
	scmpEchoMinStashDataLen       = 18
)

// isICMPv6Echo reports whether the ICMPv6 type is an Echo Request or an Echo
// Reply.
func isICMPv6Echo(tc layers.ICMPv6TypeCode) bool {
	switch tc.Type() {
	case layers.ICMPv6TypeEchoRequest, layers.ICMPv6TypeEchoReply:
		return true
	}
	return false
}

// buildSCMPEchoPayload converts the raw ICMPv6 echo payload
// (identifier(2) | sequence(2) | data) into the SCMP echo wire format:
// SCMPEcho info block (identifier(2) | sequence(2)) followed by the data
// block.
//
// The SCMPEcho identifier semantics depend on the direction:
//
//   - Echo Request: the identifier is set to DefaultSCIONEndhostPort (the
//     local SCMP underlay port that replies are routed back to). The original
//     ICMPv6 identifier is stashed at data bytes 16..17 when the data block
//     is at least 18 bytes long so the peer can restore it in the reply.
//   - Echo Reply: the identifier carries the original ICMPv6 identifier (the
//     request's identifier), which routers use as the reply's destination
//     port. The data block is returned unmodified: it already holds the
//     original identifier stashed by the request egress.
//
// For short request payloads (< 18 bytes of data) there is no room to stash
// the identifier, so the original ICMPv6 identifier is kept in the SCMPEcho
// identifier field instead (documented fallback).
func buildSCMPEchoPayload(scmpType slayers.SCMPType, raw []byte, log *scionlog.Logger) []byte {
	if len(raw) < 4 {
		log.Infof(scionlog.ComponentPath, "[ICMP6->SCMP] warning: short ICMPv6 echo payload len=%d, pass-through", len(raw))
		return raw
	}

	origID := binary.BigEndian.Uint16(raw[0:2])
	seq := binary.BigEndian.Uint16(raw[2:4])
	data := raw[4:]

	echoID := origID
	if scmpType == slayers.SCMPTypeEchoRequest {
		echoID = DefaultSCIONEndhostPort
		if len(data) >= scmpEchoMinStashDataLen {
			stashed := append([]byte(nil), data...)
			binary.BigEndian.PutUint16(stashed[scmpEchoIdentifierStashOffset:], origID)
			data = stashed
		} else {
			echoID = origID
		}
	}

	echo := &slayers.SCMPEcho{Identifier: echoID, SeqNumber: seq}
	buf := gopacket.NewSerializeBuffer()
	if err := echo.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
		log.Infof(scionlog.ComponentPath, "[ICMP6->SCMP] error: SCMPEcho serialize failed err=%v", err)
		return raw
	}
	return append(buf.Bytes(), data...)
}

// restoreICMPv6EchoID rebuilds the ICMPv6 echo payload of an SCMP Echo Reply
// received from the network. The SCMP payload is
// SCMPEcho(identifier | sequence) followed by the data block. For data blocks
// of at least 18 bytes the original ICMPv6 identifier stashed at data bytes
// 16..17 by the egress translation is restored into the ICMPv6 identifier
// field. For shorter payloads the SCMPEcho identifier is used as-is.
func restoreICMPv6EchoID(payload []byte, log *scionlog.Logger) []byte {
	if len(payload) < 4 {
		log.Infof(scionlog.ComponentPath, "[SCMP->ICMP6] warning: short SCMP echo payload len=%d, pass-through", len(payload))
		return payload
	}

	id := binary.BigEndian.Uint16(payload[0:2])
	seq := binary.BigEndian.Uint16(payload[2:4])
	data := payload[4:]

	if len(data) >= scmpEchoMinStashDataLen {
		id = binary.BigEndian.Uint16(data[scmpEchoIdentifierStashOffset:])
	}

	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], seq)
	copy(out[4:], data)
	return out
}

// translateSCMPTypeCodeToICMPv6 maps SCMP Type+Code back to ICMPv6 Type+Code.
func translateSCMPTypeCodeToICMPv6(scmpTypeCode slayers.SCMPTypeCode, log *scionlog.Logger) layers.ICMPv6TypeCode {
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
			log.Infof(scionlog.ComponentPath, "[SCMP->ICMP6] warning: unsupported SCMP DestinationUnreachable code=%d, fallback=ICMPv6 NoRoute",
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
			log.Infof(scionlog.ComponentPath, "[SCMP->ICMP6] info: SCION-specific ParameterProblem code=%d mapped to generic ICMPv6 ParameterProblem code=0",
				scmpTypeCode.Code())
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 0)

		default:
			log.Infof(scionlog.ComponentPath, "[SCMP->ICMP6] warning: unsupported SCMP ParameterProblem code=%d, fallback=ICMPv6 ParameterProblem code=0",
				scmpTypeCode.Code())
			out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeParameterProblem, 0)
		}

	case slayers.SCMPTypeExternalInterfaceDown:
		log.Infof(scionlog.ComponentPath, "[SCMP->ICMP6] info: ExternalInterfaceDown mapped to ICMPv6 DestinationUnreachable NoRoute")
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 0)

	case slayers.SCMPTypeInternalConnectivityDown:
		log.Infof(scionlog.ComponentPath, "[SCMP->ICMP6] info: InternalConnectivityDown mapped to ICMPv6 DestinationUnreachable NoRoute")
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 0)

	case slayers.SCMPTypeEchoRequest:
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)

	case slayers.SCMPTypeEchoReply:
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0)

	case slayers.SCMPTypeTracerouteRequest:
		log.Infof(scionlog.ComponentPath, "[SCMP->ICMP6] info: TracerouteRequest mapped to ICMPv6 EchoRequest")
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)

	case slayers.SCMPTypeTracerouteReply:
		log.Infof(scionlog.ComponentPath, "[SCMP->ICMP6] info: TracerouteReply mapped to ICMPv6 EchoReply")
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0)

	default:
		log.Infof(scionlog.ComponentPath, "[SCMP->ICMP6] warning: unsupported SCMP type=%d code=%d string=%s, fallback=ICMPv6 DestinationUnreachable NoRoute",
			scmpTypeCode.Type(),
			scmpTypeCode.Code(),
			scmpTypeCode.String(),
		)
		out = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, 0)
	}

	return out
}

// SCMP -> ICMPv6 translation
func scmpToICMP(scmp *slayers.SCMP, scionPayload []byte, log *scionlog.Logger) ([]byte, error) {
	icmpTypeCode := translateSCMPTypeCodeToICMPv6(scmp.TypeCode, log)

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
	log *scionlog.Logger,
) ([]byte, error) {
	log.Infof(scionlog.ComponentPath, "[BUILD-SCION] enter srcIA=%d-%d dstIA=%d-%d srcHost=%s dstHost=%s flowID=%d trafficClass=%d nextHeader=%v l4Type=%T payloadLen=%d selectedPathType=%T",
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

	log.Infof(scionlog.ComponentPath, "[BUILD-SCION] SrcIA=%v DstIA=%v", srcIA, dstIA)

	// Convert net.IP to netip.Addr
	srcAddr, err := ipToNetip(srcHost)
	if err != nil {
		return nil, fmt.Errorf("convert srcHost: %w", err)
	}

	dstAddr, err := ipToNetip(dstHost)
	if err != nil {
		return nil, fmt.Errorf("convert dstHost: %w", err)
	}

	pkt.SetSrcAddr(addr.HostIP(srcAddr))
	pkt.SetDstAddr(addr.HostIP(dstAddr))

	log.Infof(scionlog.ComponentPath, "[BUILD-SCION] host addresses set srcHost=%s dstHost=%s srcAddrType=%v dstAddrType=%v",
		ipString(srcHost),
		ipString(dstHost),
		pkt.SrcAddrType,
		pkt.DstAddrType,
	)

	dp := selectedpath.Dataplane()
	if dp != nil {
		if err := dp.SetPath(pkt); err != nil {
			return nil, fmt.Errorf("set dataplane selectedpath: %w", err)
		}
	} else {
		pkt.PathType = empty.PathType
		pkt.Path = empty.Path{}
	}

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

	case *slayers.SCMP:
		// gopacket cannot compute the SCMP checksum for SCION packets, so we
		// serialize the SCMP header (checksum 0) and compute the checksum over
		// SCMP header + info block + data with the SCION pseudo header
		// (mirrors the TCP case below). The info block and data are carried in
		// l4Payload (see buildSCMPEchoPayload).
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: false,
		}

		hdrbuf := gopacket.NewSerializeBuffer()
		if err := l.SerializeTo(hdrbuf, gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: false,
		}); err != nil {
			return nil, fmt.Errorf("serialize SCMP for checksum: %w", err)
		}
		scmpBytes := hdrbuf.Bytes()

		upperLen := uint16(len(scmpBytes) + len(l4Payload))

		pseudo, err := buildSCIONPseudoHeader(
			srcIA, dstIA,
			srcHost, dstHost,
			upperLen,
			slayers.L4SCMP,
		)
		if err != nil {
			return nil, fmt.Errorf("build SCION SCMP pseudo header: %w", err)
		}

		bufForCksum := make([]byte, 0, len(pseudo)+len(scmpBytes)+len(l4Payload))
		bufForCksum = append(bufForCksum, pseudo...)
		bufForCksum = append(bufForCksum, scmpBytes...)
		bufForCksum = append(bufForCksum, l4Payload...)

		l.Checksum = checksum16(bufForCksum)

		if err := gopacket.SerializeLayers(buf, opts,
			pkt,
			l4layer,
			gopacket.Payload(l4Payload),
		); err != nil {
			return nil, fmt.Errorf("failed to serialize SCION+SCMP: %w", err)
		}

	default:
		// If you ever pass something else, checksums won’t be computed correctly.
		return nil, fmt.Errorf("unsupported L4 layer type %T; expected *slayers.UDP or *layers.TCP", l4layer)
	}

	//SetNetworkLayerForChecmsum only accepts *layers.IPv4 or IPv6? Does not work with *slyers.SCION for pkt.

	//---------------------------------------------------------------------------------------------------------

	out := buf.Bytes()
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
