package device

import (
	"net"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/scionlog"
)

func makePeer(t *testing.T) *Peer {
	t.Helper()
	return &Peer{}
}

func insertPrefix(t *testing.T, allowed *AllowedIPs, prefix string, peer *Peer) {
	t.Helper()
	pfx := netip.MustParsePrefix(prefix)
	allowed.Insert(pfx, peer)
}

func TestPeerSelection_SCIONOriginalMappedDst(t *testing.T) {
	var allowed AllowedIPs
	scionPeer := makePeer(t)
	insertPrefix(t, &allowed, "fc00::/8", scionPeer)

	dst := net.ParseIP("fc04:7800:4a00::ffff:8d2c:1996").To16()
	if dst == nil {
		t.Fatal("failed to parse test IP")
	}

	peer := allowed.Lookup(dst)
	if peer == nil {
		t.Fatal("SCION-mapped IPv6 dst should find peer via fc00::/8")
	}
	if peer != scionPeer {
		t.Fatal("peer should be the fc00::/8 peer")
	}
}

func TestPeerSelection_NoPostTranslationLookup(t *testing.T) {
	var allowed AllowedIPs
	scionPeer := makePeer(t)
	insertPrefix(t, &allowed, "fc00::/8", scionPeer)

	translatedDst := net.ParseIP("141.44.25.150").To4()
	if translatedDst == nil {
		t.Fatal("failed to parse test IP")
	}

	peer := allowed.Lookup(translatedDst)
	if peer != nil {
		t.Fatal("translated IPv4 dst 141.44.25.150 should NOT find peer when not in AllowedIPs")
	}

	originalDst := net.ParseIP("fc04:7800:4a00::ffff:8d2c:1996").To16()
	peer = allowed.Lookup(originalDst)
	if peer == nil {
		t.Fatal("original SCION-mapped dst should still find peer via fc00::/8")
	}
}

func TestPeerSelection_SCIONLookupFailsWithoutFC00(t *testing.T) {
	var allowed AllowedIPs
	otherPeer := makePeer(t)
	insertPrefix(t, &allowed, "10.44.25.0/24", otherPeer)

	dst := net.ParseIP("fc04:7800:4a00::ffff:8d2c:1996").To16()
	if dst == nil {
		t.Fatal("failed to parse test IP")
	}

	peer := allowed.Lookup(dst)
	if peer != nil {
		t.Fatal("without fc00::/8, SCION-mapped dst should return nil peer")
	}
}

func TestPeerSelection_NormalIPv4(t *testing.T) {
	var allowed AllowedIPs
	v4Peer := makePeer(t)
	insertPrefix(t, &allowed, "10.44.25.0/24", v4Peer)

	dst := net.ParseIP("10.44.25.70").To4()
	if dst == nil {
		t.Fatal("failed to parse test IP")
	}

	peer := allowed.Lookup(dst)
	if peer == nil {
		t.Fatal("normal IPv4 dst should find peer")
	}
	if peer != v4Peer {
		t.Fatal("peer should match 10.44.25.0/24")
	}
}

func TestPeerSelection_NormalIPv6(t *testing.T) {
	var allowed AllowedIPs
	v6Peer := makePeer(t)
	insertPrefix(t, &allowed, "fd00::/8", v6Peer)

	dst := net.ParseIP("fd42:42:42::1").To16()
	if dst == nil {
		t.Fatal("failed to parse test IP")
	}

	peer := allowed.Lookup(dst)
	if peer == nil {
		t.Fatal("normal IPv6 dst should find peer")
	}
	if peer != v6Peer {
		t.Fatal("peer should match fd00::/8")
	}
}

func TestPeerSelection_InterAS_SCION(t *testing.T) {
	var allowed AllowedIPs
	scionPeer := makePeer(t)
	insertPrefix(t, &allowed, "fc00::/8", scionPeer)
	insertPrefix(t, &allowed, "141.44.25.151/32", scionPeer)

	dst := net.ParseIP("fc04:7800:4b00::ffff:8d2c:1996").To16()
	if dst == nil {
		t.Fatal("failed to parse test IP")
	}

	peer := allowed.Lookup(dst)
	if peer == nil {
		t.Fatal("inter-AS SCION dst should find peer via fc00::/8")
	}
	if peer != scionPeer {
		t.Fatal("peer should be the fc00::/8 peer")
	}

	brDst := net.ParseIP("141.44.25.151").To4()
	peer = allowed.Lookup(brDst)
	if peer == nil {
		t.Fatal("BR IP should find peer via 141.44.25.151/32")
	}
}

func TestPeerSelection_SameAS_EmptyPath(t *testing.T) {
	var allowed AllowedIPs
	scionPeer := makePeer(t)
	insertPrefix(t, &allowed, "fc00::/8", scionPeer)

	originalDst := net.ParseIP("fc04:7800:4a00::ffff:8d2c:1996").To16()
	if originalDst == nil {
		t.Fatal("failed to parse test IP")
	}

	peer := allowed.Lookup(originalDst)
	if peer == nil {
		t.Fatal("same-AS SCION dst should find peer via fc00::/8")
	}
	if peer != scionPeer {
		t.Fatal("peer should be the fc00::/8 peer")
	}

	translatedDst := net.ParseIP("141.44.25.150").To4()
	peer = allowed.Lookup(translatedDst)
	if peer != nil {
		t.Fatal("translated same-AS IPv4 dst should NOT find peer (not in AllowedIPs)")
	}
}

func testDevice(allowed AllowedIPs) *Device {
	return &Device{
		allowedips: allowed,
		log: &Logger{
			Verbosef: func(format string, args ...any) {},
			Errorf:   func(format string, args ...any) {},
		},
		scionLog: scionlog.NewLogger(
			func(format string, args ...any) {},
			func(format string, args ...any) {},
		),
	}
}

func TestLookupPeerForPacket_SCIONv6(t *testing.T) {
	var allowed AllowedIPs
	scionPeer := makePeer(t)
	insertPrefix(t, &allowed, "fc00::/8", scionPeer)

	device := testDevice(allowed)

	pkt := make([]byte, 40)
	pkt[0] = 0x60
	srcIP := net.ParseIP("fd42:42:42::70").To16()
	copy(pkt[IPv6offsetSrc:IPv6offsetSrc+net.IPv6len], srcIP)
	dstIP := net.ParseIP("fc04:7800:4a00::ffff:8d2c:1996").To16()
	copy(pkt[IPv6offsetDst:IPv6offsetDst+net.IPv6len], dstIP)

	peer := device.lookupPeerForPacket(pkt)
	if peer == nil {
		t.Fatal("lookupPeerForPacket should find peer for SCION-mapped IPv6 dst via fc00::/8")
	}
	if peer != scionPeer {
		t.Fatal("lookupPeerForPacket should return the fc00::/8 peer")
	}
}

func TestLookupPeerForPacket_IPv4(t *testing.T) {
	var allowed AllowedIPs
	v4Peer := makePeer(t)
	insertPrefix(t, &allowed, "10.44.25.0/24", v4Peer)

	device := testDevice(allowed)

	pkt := make([]byte, 20)
	pkt[0] = 0x45
	dstIP := net.ParseIP("10.44.25.70").To4()
	copy(pkt[IPv4offsetDst:IPv4offsetDst+net.IPv4len], dstIP)

	peer := device.lookupPeerForPacket(pkt)
	if peer == nil {
		t.Fatal("lookupPeerForPacket should find peer for IPv4 dst")
	}
	if peer != v4Peer {
		t.Fatal("lookupPeerForPacket should return the 10.44.25.0/24 peer")
	}
}

func TestLookupPeerForPacket_IPv6NonSCION(t *testing.T) {
	var allowed AllowedIPs
	v6Peer := makePeer(t)
	insertPrefix(t, &allowed, "fd00::/8", v6Peer)

	device := testDevice(allowed)

	pkt := make([]byte, 40)
	pkt[0] = 0x60
	srcIP := net.ParseIP("fe80::1").To16()
	copy(pkt[IPv6offsetSrc:IPv6offsetSrc+net.IPv6len], srcIP)
	dstIP := net.ParseIP("fd42:42:42::70").To16()
	copy(pkt[IPv6offsetDst:IPv6offsetDst+net.IPv6len], dstIP)

	peer := device.lookupPeerForPacket(pkt)
	if peer == nil {
		t.Fatal("lookupPeerForPacket should find peer for non-SCION IPv6 dst")
	}
	if peer != v6Peer {
		t.Fatal("lookupPeerForPacket should return the fd00::/8 peer")
	}
}

func TestLookupPeerForPacket_ShortPacket(t *testing.T) {
	device := testDevice(AllowedIPs{})

	peer := device.lookupPeerForPacket(nil)
	if peer != nil {
		t.Fatal("nil packet should return nil peer")
	}

	peer = device.lookupPeerForPacket([]byte{})
	if peer != nil {
		t.Fatal("empty packet should return nil peer")
	}

	peer = device.lookupPeerForPacket([]byte{0x60, 0, 0, 0, 0, 0, 0, 0})
	if peer != nil {
		t.Fatal("short IPv6 packet should return nil peer")
	}

	peer = device.lookupPeerForPacket([]byte{0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if peer != nil {
		t.Fatal("short IPv4 packet should return nil peer")
	}
}

func TestPeerSelection_SameAS_141_44_25_150_NotRequired(t *testing.T) {
	var allowed AllowedIPs
	scionPeer := makePeer(t)
	insertPrefix(t, &allowed, "fc00::/8", scionPeer)
	insertPrefix(t, &allowed, "141.44.25.151/32", scionPeer)
	insertPrefix(t, &allowed, "10.44.25.0/24", scionPeer)

	tests := []struct {
		name    string
		ip      string
		wantNil bool
	}{
		{"original SCION-mapped dst", "fc04:7800:4a00::ffff:8d2c:1996", false},
		{"border router IP", "141.44.25.151", false},
		{"tunnel network IP", "10.44.25.70", false},
		{"translated SCION host IP", "141.44.25.150", true},
		{"unrelated IP", "8.8.8.8", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			var lookupIP []byte
			if ip4 := ip.To4(); ip4 != nil {
				lookupIP = ip4
			} else {
				lookupIP = ip.To16()
			}
			peer := allowed.Lookup(lookupIP)
			if tt.wantNil && peer != nil {
				t.Errorf("expected nil peer for %s, got peer", tt.ip)
			}
			if !tt.wantNil && peer == nil {
				t.Errorf("expected peer for %s, got nil", tt.ip)
			}
		})
	}
}

func TestPeerSelection_CountLookups(t *testing.T) {
	var allowed AllowedIPs
	scionPeer := makePeer(t)
	insertPrefix(t, &allowed, "fc00::/8", scionPeer)

	lookupCount := 0
	lookedUp := func(ip []byte) *Peer {
		lookupCount++
		return allowed.Lookup(ip)
	}

	origDst := net.ParseIP("fc04:7800:4a00::ffff:8d2c:1996").To16()
	translatedDst := net.ParseIP("141.44.25.150").To4()

	peer := lookedUp(origDst)
	if peer == nil {
		t.Fatal("original dst should find peer")
	}
	if lookupCount != 1 {
		t.Fatalf("expected 1 lookup after original dst, got %d", lookupCount)
	}

	peer = lookedUp(translatedDst)
	if peer != nil {
		t.Fatal("translated dst should NOT find peer")
	}
	if lookupCount != 2 {
		t.Fatalf("expected 2 lookups total, got %d", lookupCount)
	}
}
