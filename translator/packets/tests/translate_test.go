package packets

//https://pkg.go.dev/github.com/scionproto/scion@v0.12.0/pkg/slayers#SCION.Path

import (
	"bytes"
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/scionproto/scion/pkg/slayers"

	"golang.zx2c4.com/wireguard/translator/header_parsing"
)

/*
func TestTranslateEgress_IPv6toSCION_UDP(t *testing.T) {
	// synthetic IPv6/UDP packet
	ipv6 := &layers.IPv6{
		SrcIP:      net.ParseIP("fc00:10fc::1"),
		DstIP:      net.ParseIP("fc00:10fc::2"),
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   16,
	}

	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 80,
	}
	udp.SetNetworkLayerForChecksum(ipv6)

	payload := gopacket.Payload([]byte("hello scion"))

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buffer, opts, ipv6, udp, payload))
	pktData := buffer.Bytes()

	// call translation function
	cache := &DummyPathCache{}
	scionData, _, err := TranslateEgress(pktData, net.ParseIP("2001:db8::127.0.0.1"), 30000, cache)
	if err != nil {
		t.Errorf("TranslateEgress failed: %v", err) // automatically prints any errors.New
	}
	scionPkt := gopacket.NewPacket(scionData, slayers.LayerTypeSCION, gopacket.Default)

	require.NotNil(t, scionPkt, "Translation should produce a SCION byte slice")
	//require.NotNil(t, nextHop, "Next hop must not be nil")
	require.NoError(t, err, "Translation should not produce an error")

	scionLayer := scionPkt.Layer(slayers.LayerTypeSCION)
	require.NotNil(t, scionLayer, "SCION header must exist")

	scion, _ := scionLayer.(*slayers.SCION)
	require.Equal(t, uint16(1), scion.DstIA, "Destination IA should be set")
	require.Equal(t, uint32(0xffaa), scion.SrcIA, "Source IA should be set")

	udpLayer := scionPkt.Layer(layers.LayerTypeUDP)
	require.NotNil(t, udpLayer, "SCION packet must carry UDP payload")
	udpOut, _ := udpLayer.(*layers.UDP)
	require.Equal(t, uint16(12345), uint16(udpOut.SrcPort))
	require.Equal(t, uint16(54321), uint16(udpOut.DstPort))

	payloadLayer := scionPkt.ApplicationLayer()
	require.Equal(t, []byte("hello scion"), payloadLayer.Payload())
}
*/

// -----------------------------------------------------------------------------
// Paths
// -----------------------------------------------------------------------------

const (
	// IP_BASE_PATH = "wireguard-go/translator/packets/ipv6/"
	IP_BASE_PATH = ""

	TCP_BASIC        = IP_BASE_PATH + "../ipv6/input/tcp_basic.bin"
	UDP_BASIC        = IP_BASE_PATH + "../ipv6/input/udp_basic.bin"
	UDP_INVALID_ADDR = IP_BASE_PATH + "../ipv6/input/udp_invalid_addr.bin"

	TCP_BASIC_SCION = IP_BASE_PATH + "../ipv6/exp/tcp_basic_scion.bin"
	UDP_BASIC_SCION = IP_BASE_PATH + "../ipv6/exp/udp_basic_scion.bin"
)

//--------------------------Read/Write---------------------------

//ToDo: Extenstion to read multiple files

func loadScionBin(file string) ([]byte, error) {
	return os.ReadFile(file)
}

func loadIPv6Bin(file string) ([]byte, error) {
	return os.ReadFile(file)
}

//--------------------------- DECODE -----------------------------

func decodeIPv6(b []byte) layers.IPv6 {

	var out layers.IPv6

	out.DecodeFromBytes(b, gopacket.NilDecodeFeedback)

	return out
}

func decodeScionBytes(b []byte) slayers.SCION {

	var out slayers.SCION

	out.DecodeFromBytes(b, gopacket.NilDecodeFeedback)

	return out
}

//-------------------------- COMPARE ----------------------------

// Compare Egress
func compareSCION(got, want *slayers.SCION) bool {

	if got == nil || want == nil {
		return got == want
	}

	return true
}

// Compare Ingress
func compareIPv6(got, want *layers.IPv6) bool {
	if got == nil || want == nil {
		return got == want
	}

	if got.Version != want.Version {
		return false
	}
	if got.TrafficClass != want.TrafficClass {
		return false
	}
	if got.FlowLabel != want.FlowLabel {
		return false
	}
	if got.NextHeader != want.NextHeader {
		return false
	}
	if got.HopLimit != want.HopLimit {
		return false
	}

	// addresses (use Equal to handle 16 vs 4/16 forms)
	if !got.SrcIP.Equal(want.SrcIP) {
		return false
	}
	if !got.DstIP.Equal(want.DstIP) {
		return false
	}

	// If you decoded L4/payload separately, compare those too.
	return true
}

func compareAddrSCION(got, want *slayers.SCION) bool {

	if got == nil || want == nil {
		return got == want
	}

	if got.SrcIA != want.SrcIA {
		return false
	}

	if got.DstIA != want.DstIA {
		return false
	}

	return true
}

func comparePayloadSCION(got, want *slayers.SCION) bool {

	if string(got.Payload) != string(want.Payload) {
		return false
	}

	return true
}

func compareRawAddrSCION(got, want *slayers.SCION) bool {

	if got.RawSrcAddr == nil || want.RawSrcAddr == nil {
		return false
	}

	if !bytes.Equal(got.RawSrcAddr, want.RawSrcAddr) {
		return false
	}

	if !bytes.Equal(got.RawDstAddr, want.RawDstAddr) {
		return false
	}

	return true
}

//--------------------------- TEST ------------------------------

func Test_BasicTCP_IPv6ToSCION(t *testing.T) {

	// Load IP Packet bytes from .bin
	ipraw, err := loadIPv6Bin(TCP_BASIC)
	if err != nil {
		t.Fatalf("Error during loading of IPv6 bytes from .bin: %v", err)
	}
	var temp layers.IPv6
	temp.DecodeFromBytes(ipraw, gopacket.NilDecodeFeedback)
	ipkt := gopacket.NewPacket(ipraw, layers.LayerTypeIPv6, gopacket.Default)

	var srcPort int
	if tcpLayer := ipkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		// fmt.Printf("TCP srcPort=%d dstPort=%d flags=%v\n", tcp.SrcPort, tcp.DstPort, tcp.Flags)
		srcPort = int(tcp.SrcPort)
	}

	var dummy *header_parsing.DummyPathCache
	translated, _, err := header_parsing.TranslateEgress(ipraw, temp.SrcIP, srcPort, dummy)
	if err != nil {
		t.Fatalf("Error during IPv6 Egress Translation: %v", err)
	}

	var translatedscion slayers.SCION
	translatedscion.DecodeFromBytes(translated, gopacket.NilDecodeFeedback)

	scionBytes, err := loadScionBin(TCP_BASIC_SCION)
	if err != nil {
		t.Fatalf("Error during loading of SCION bytes from .bin: %v", err)
	}
	expected := decodeScionBytes(scionBytes)

	if !compareSCION(&expected, &translatedscion) {
		t.Fatalf("Translated SCION packet does not match expected: %v", err)
	}
	if !compareAddrSCION(&expected, &translatedscion) {
		t.Fatalf("Translated SCION addresses do not match expected: %v", err)
	}
	if !comparePayloadSCION(&expected, &translatedscion) {
		t.Fatalf("Translated SCION payload does not match expected: %v", err)
	}
	if !compareRawAddrSCION(&expected, &translatedscion) {
		t.Fatalf("Translated SCION raw addresses do not match expected: %v", err)
	}

}

// Ingress Test
// func Test_TranslateIngress_ScionToIPv6(t *testing.T) {

// 	// Load Scion Packet bytes from .bin
// 	scionraw, err := loadScionBin(SCION_Packet)
// 	if err != nil {
// 		t.Fatalf("Error during loading of SCION bytes from .bin: %v", err)
// 	}

// 	var temp slayers.SCION

// 	temp.DecodeFromBytes(scionraw, gopacket.NilDecodeFeedback)

// 	dstaddr := temp.RawDstAddr

// 	// Pass Bytes to Translate function
// 	translatedbytes, err := header_parsing.TranslateIngress(scionraw, dstaddr)
// 	if err != nil {
// 		t.Fatalf("Error during SCION Ingress Translation: %v", err)
// 	}

// 	// Decode Translate Function Bytes
// 	var translatedIP layers.IPv6
// 	translatedIP.DecodeFromBytes(translatedbytes, gopacket.NilDecodeFeedback)

// 	// Load IP Packet bytes from .bin
// 	ipraw, err := loadIPv6Bin(IPv6_Packet)
// 	if err != nil {
// 		t.Fatalf("Error during loading of IPv6 bytes from .bin: %v", err)
// 	}

// 	// Decode IP Packet bytes
// 	targetIP := decodeIPv6(ipraw)

// 	// Compare Target and Translated IP Packet
// 	compareIPv6(&targetIP, &translatedIP)

// }

// Engress Test
// func Test_TranslateEgress_IPv6ToScion(t *testing.T) {

// 	// Load IP Packet bytes from .bin
// 	ipraw, err := loadIPv6Bin(IPv6_Packet)
// 	if err != nil {
// 		t.Fatalf("Error during loading of IPv6 bytes from .bin: %v", err)
// 	}

// 	var temp layers.IPv6

// 	temp.DecodeFromBytes(ipraw, gopacket.NilDecodeFeedback)

// 	//Path Cache
// 	var dummy *header_parsing.DummyPathCache

// 	// Cache need host + port

// 	payload := ipraw[40:]

// 	var hostport int

// 	//Port
// 	if temp.NextHeader == layers.IPProtocolUDP {
// 		udp := layers.UDP{}
// 		udp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback)
// 		hostport = int(udp.SrcPort)
// 	}

// 	// Load Scion Packet bytes from .bin
// 	scionraw, err := loadScionBin(SCION_Packet)
// 	if err != nil {
// 		t.Fatalf("Error during loading of SCION Bytes from .bin: %v", err)
// 	}

// 	// Decode Scion Packet bytes
// 	targetscion := decodeScionBytes(scionraw)

// 	// Pass Bytes to Translate function
// 	translatedbytes, _, err := header_parsing.TranslateEgress(ipraw, temp.SrcIP, hostport, dummy)
// 	if err != nil {
// 		t.Fatalf("TranslateEgress Error: %v", err)
// 	}

// 	//_ is net.UPDAddr

// 	// Decode Translate Function Bytes
// 	var translatedscion slayers.SCION
// 	translatedscion.DecodeFromBytes(translatedbytes, gopacket.NilDecodeFeedback)

// 	// Compare Target and Translated Scion Packet
// 	if !compareSCION(&targetscion, &translatedscion) {

// 		t.Fatalf("Egress Translated SCION Packet not equal: %v", err)
// 	}

// }
