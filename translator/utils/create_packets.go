// package translator

package main

//ToDo: Add IP Packet creation so .py script becomes redudant!

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"

	//"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
)

// GenerateSCIONPacket creates a minimal SCION packet (UDP only) and saves it to a .bin file.
// filename: where to save the packet
// srcISD/srcAS, dstISD/dstAS: source and destination ISD-AS
// srcIP, dstIP: source and destination IPs
func GenerateSCIONPacket(filename string, srcISD, srcAS, dstISD, dstAS int, srcIP, dstIP string) error {
	var pkt slayers.SCION

	// Create source and destination IA
	srcIA, err := addr.IAFrom(addr.ISD(srcISD), addr.AS(srcAS))
	if err != nil {
		return fmt.Errorf("failed to create source IA: %w", err)
	}
	dstIA, err := addr.IAFrom(addr.ISD(dstISD), addr.AS(dstAS))
	if err != nil {
		return fmt.Errorf("failed to create destination IA: %w", err)
	}

	pkt.SrcIA = srcIA
	pkt.DstIA = dstIA

	// Parse IPs
	pkt.RawSrcAddr = net.ParseIP(srcIP)
	pkt.RawDstAddr = net.ParseIP(dstIP)

	pkt.Path = &empty.Path{}
	pkt.Payload = []byte("Payload")

	// UDP only
	pkt.NextHdr = slayers.L4UDP

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := pkt.SerializeTo(buf, opts); err != nil {
		return fmt.Errorf("failed to serialize SCION packet: %w", err)
	}

	// Ensure output directory exists
	if err := os.MkdirAll("packets/scion_packets", 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Save to file
	if err := os.WriteFile(filename, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write SCION packet to %s: %w", filename, err)
	}

	fmt.Printf("Generated SCION packet: %s\n", filename)
	return nil
}

// generateIPv6Packet builds and saves a minimal IPv6 + UDP/TCP packet to a .bin file.
// Parameters:
// - filename: path where the packet will be saved
// - srcIP, dstIP: IPv6 addresses
// - srcPort, dstPort: transport layer ports
// - payload: data to include in the packet
// - protocol: "udp" or "tcp"
func GenerateIPv6Packet(filename, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, protocol string) error {
	ipSrc := net.ParseIP(srcIP)
	ipDst := net.ParseIP(dstIP)
	if ipSrc == nil || ipDst == nil || ipSrc.To16() == nil || ipDst.To16() == nil {
		return fmt.Errorf("invalid IPv6 address: src=%q dst=%q", srcIP, dstIP)
	}

	ip6 := &layers.IPv6{
		Version:  6,
		SrcIP:    ipSrc,
		DstIP:    ipDst,
		HopLimit: 64,
	}

	var (
		transport gopacket.SerializableLayer
		nextHdr   layers.IPProtocol
	)

	switch strings.ToLower(protocol) {
	case "udp":
		nextHdr = layers.IPProtocolUDP
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		udp.SetNetworkLayerForChecksum(ip6)
		transport = udp

	case "tcp":
		nextHdr = layers.IPProtocolTCP
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			SYN:     true,
			Window:  14600,
		}
		tcp.SetNetworkLayerForChecksum(ip6)
		transport = tcp

	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	ip6.NextHeader = nextHdr

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts,
		ip6,
		transport,
		gopacket.Payload(payload),
	); err != nil {
		return fmt.Errorf("serialize IPv6 %s: %w", protocol, err)
	}

	// Ensure target directory exists
	// if err := os.MkdirAll("packets/ip_packets", 0755); err != nil {
	// 	return fmt.Errorf("failed to create output dir: %w", err)
	// }

	// Save to file
	if err := os.WriteFile(filename, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write packet to %s: %w", filename, err)
	}

	fmt.Printf("Generated IPv6 %s packet: %s\n", strings.ToUpper(protocol), filename)
	return nil
}

func main() {
	//----------------------------TEST 1----------------------------
	err := GenerateIPv6Packet(
		"translator/packets/ipv6/input/tcp_basic.bin",
		"fc00:10fc::ffff:a80:1", "fc10:10fc::ffff:a80:2", // src and dst IPv6
		1234, 5678, // src and dst ports
		[]byte("basic tcp packet"),
		"tcp",
	)
	if err != nil {
		panic(err)
	}
	err = GenerateSCIONPacket(
		"translator/packets/ipv6/exp/tcp_basic_scion.bin",
		1, 64512, // src ISD/AS
		257, 64512, // dst ISD/AS
		"10.128.0.1", "10.128.0.2", // src/dst IPs
	)
	if err != nil {
		panic(err)
	}

	//----------------------------TEST 2----------------------------
	err = GenerateIPv6Packet(
		"translator/packets/ipv6/input/udp_basic.bin",
		"fc00:10fc::ffff:a80:1", "fc10:10fc::ffff:a80:2", // src and dst IPv6
		1234, 5678, // src and dst ports
		[]byte("basic udp payload"),
		"udp",
	)
	if err != nil {
		panic(err)
	}
	err = GenerateSCIONPacket(
		"translator/packets/ipv6/exp/udp_basic_scion.bin",
		1, 64512, // src ISD/AS
		257, 64512, // dst ISD/AS
		"10.128.0.1", "10.128.0.2", // src/dst IPs
	)
	if err != nil {
		panic(err)
	}

	//----------------------------TEST 3----------------------------

	err = GenerateIPv6Packet(
		"translator/packets/ipv6/input/udp_invalid_addr.bin",
		"fc00:10fc::ffff:a80:1", "fd00:10fc::ffff:a80:1", // src and dst IPv6
		1234, 5678, // src and dst ports
		[]byte("not IPv6-mapped SCION address"),
		"udp",
	)
	if err != nil {
		panic(err)
	}
}
