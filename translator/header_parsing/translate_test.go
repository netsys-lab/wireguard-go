package header_parsing

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/stretchr/testify/require"
	//"translator/header_parsing"
)

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
