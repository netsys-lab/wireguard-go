package translator

//package main

//ToDo: Add IP Packet creation so .py script becomes redudant!

import (
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"

	//"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
)

func generateSCIONPacket(srcISD int, srcAS int, dstISD int, dstAS int, srcIP string, dstIP string) slayers.SCION {
	var scion slayers.SCION

	srcIA, srcerr := addr.IAFrom(addr.ISD(srcISD), addr.AS(srcAS))
	if srcerr != nil {
		panic("Failed to create IA from ISD and AS")
	}
	dstIA, dsterr := addr.IAFrom(addr.ISD(dstISD), addr.AS(dstAS))

	if dsterr != nil {
		panic("Failed to create IA from ISD and AS")
	}

	scion.SrcIA = srcIA
	scion.DstIA = dstIA

	scion.RawSrcAddr = net.ParseIP(srcIP)
	scion.RawDstAddr = net.ParseIP(dstIP)

	scion.Path = &empty.Path{}
	scion.Payload = []byte("Payload")

	scion.NextHdr = slayers.L4TCP

	return scion
}

func SerializeSCIONPacket(s slayers.SCION) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := s.SerializeTo(buf, opts); err != nil {
		panic(fmt.Sprintf("failed to serialize SCION packet: %v", err))
	}
	return buf.Bytes()
}

func SaveSCIONPacketToBin(filename string, pkt slayers.SCION) {
	raw := SerializeSCIONPacket(pkt)
	if err := os.WriteFile(filename, raw, 0644); err != nil {
		panic(fmt.Sprintf("failed to write SCION packet to %s: %v", filename, err))
	}
}

func createSCIONPacket(filename string, srcISD int, srcAS int, dstISD int, dstAS int, srcIP string, dstIP string) {

	pkt := generateSCIONPacket(srcISD, srcAS, dstISD, dstAS, srcIP, dstIP)
	SaveSCIONPacketToBin(filename, pkt)

}

// generateIPv6UDP builds a minimal IPv6 + UDP packet with given IPs, ports, payload.
// It returns raw bytes ready to be written to a .bin file.
func generateIPv6UDP(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	ipSrc := net.ParseIP(srcIP)
	ipDst := net.ParseIP(dstIP)
	if ipSrc == nil || ipDst == nil || ipSrc.To16() == nil || ipDst.To16() == nil {
		return nil, fmt.Errorf("invalid IPv6 address: src=%q dst=%q", srcIP, dstIP)
	}

	ip6 := &layers.IPv6{
		Version:    6,
		SrcIP:      ipSrc,
		DstIP:      ipDst,
		NextHeader: layers.IPProtocolUDP,
		HopLimit:   64,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	// UDP checksum is mandatory in IPv6; this ensures correct computation.
	udp.SetNetworkLayerForChecksum(ip6)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true, // fills IPv6 payload length and UDP length
		ComputeChecksums: true, // computes UDP checksum
	}

	if err := gopacket.SerializeLayers(buf, opts,
		ip6,
		udp,
		gopacket.Payload(payload),
	); err != nil {
		return nil, fmt.Errorf("serialize IPv6 UDP: %w", err)
	}

	return buf.Bytes(), nil
}

func SaveIPv6UDPPacketToBin(filename, srcIP, dstIP string, srcPort, dstPort uint16) {
	raw, err := generateIPv6UDP(srcIP, dstIP, srcPort, dstPort, []byte("Payload"))
	if err != nil {
		panic(fmt.Sprintf("failed to generate IPv6 UDP packet: %v", err))
	}
	if err := os.WriteFile(filename, raw, 0644); err != nil {
		panic(fmt.Sprintf("failed to write IPv6 UDP packet to %s: %v", filename, err))
	}
}

func createIPv6UDPPacket(filename, srcIP, dstIP string, srcPort, dstPort uint16) {
	SaveIPv6UDPPacketToBin(filename, srcIP, dstIP, srcPort, dstPort)
}

func GenerateScionPackets() {

	os.MkdirAll("packets/scion_packets", 0755)

	//createSCIONPacket("packets/scion_packets/test1.bin", 1, 0xfc000110, 1, 0xfc000110, "127.0.0.5", "127.0.0.4")
	createSCIONPacket("packets/scion_packets/test1.bin", 1, 0x0000FC00, 1, 0x0000FC00, "10.128.0.1", "10.128.0.1")
}

func GenerateIPv6Packets() {

	os.MkdirAll("packets/ip_packets", 0755)

	//createIPv6UDPPacket("packets/ip_packets/test1.bin", "fc00:0:0:1::c000:201", "fc00:0:0:1::c000:202", 30042, 30042)
	createIPv6UDPPacket("packets/ip_packets/test1.bin", "fc00:10fc::ffff:a80:1", "fc00:10fc::ffff:a80:1", 30042, 30042)
}

func main() {
	GenerateScionPackets()
	GenerateIPv6Packets()
}
