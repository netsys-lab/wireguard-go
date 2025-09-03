package translator

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/scionproto/scion/pkg/slayers"

	//"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/pkg/slayers/path/empty"
)

// Run Python script to generate packages
func createPackets(t *testing.T) {
	cmd := exec.Command("python3", "create_packets.py")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	GenerateScionPackets()

	//If Package creation has an error
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to run python script to generate packages: %v\nOuput: %s", err, out.String())
	}

	GenerateScionPackets()
}

// Load a SCION packet from raw .bin file
func loadScionPacketFromBin(t *testing.T, filename string) slayers.SCION {
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read SCION bin file %s: %v", filename, err)
	}

	var scion slayers.SCION
	decoded := []gopacket.LayerType{}

	parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION, &scion)
	parser.IgnoreUnsupported = true

	if err := parser.DecodeLayers(data, &decoded); err != nil {
		t.Fatalf("failed to decode SCION packet %s: %v", filename, err)
		scion.Path = &empty.Path{}

	} else {
		// Ensure path is at least an empty path if nil
		if scion.Path == nil {
			scion.Path = &empty.Path{}
		}
	}

	return scion
}

// Example: load multiple SCION .bin packets from a directory
func loadScionPacketsFromBinDir(t *testing.T, dir string) []slayers.SCION {
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read dir %s: %v", dir, err)
	}

	var packets []slayers.SCION
	for _, f := range files {
		scion := loadScionPacketFromBin(t, dir+"/"+f.Name())
		packets = append(packets, scion)
	}
	return packets
}

// Load Scion Packets
func loadScionPackets(t *testing.T) []slayers.SCION {

	pcapSCIONDir := "packets/scion_packets"

	var scionPackets []slayers.SCION

	files, err := os.ReadDir(pcapSCIONDir)
	if err != nil {
		t.Fatalf("failed to read %s: %v", pcapSCIONDir, err)
	}
	if len(files) == 0 {
		t.Fatalf("no pcap files in %s", pcapSCIONDir)
	}

	for _, f := range files {
		handle, err := pcap.OpenOffline(filepath.Join(pcapSCIONDir, f.Name()))
		if err != nil {
			t.Fatalf("failed to open pcap %s: %v", f.Name(), err)
		}

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for pkt := range packetSource.Packets() {
			var scion slayers.SCION
			parser := gopacket.NewDecodingLayerParser(slayers.LayerTypeSCION, &scion)
			parser.IgnoreUnsupported = true
			decoded := []gopacket.LayerType{}

			if err := parser.DecodeLayers(pkt.Data(), &decoded); err != nil {
				t.Logf("decode error in %s: %v", f.Name(), err)
				continue
			}

			scionPackets = append(scionPackets, scion)
		}

		defer handle.Close()

	}
	return scionPackets
}

func loadIpPackets(t *testing.T) []gopacket.Packet {

	//Path to ip packet directory
	pcapIPDir := "packets/ip_packets"

	var ipPackets []gopacket.Packet

	//Read filenames in directory
	files, err := os.ReadDir(pcapIPDir)
	if err != nil {
		t.Fatalf("failed to read %s: %v", pcapIPDir, err)
	}
	if len(files) == 0 {
		t.Fatalf("no pcap files generated in %s", pcapIPDir)
	}

	//Iterate pcap filenames
	for _, f := range files {

		//Decode packets in each pcap file
		handle, err := pcap.OpenOffline(filepath.Join(pcapIPDir, f.Name()))
		if err != nil {
			t.Fatalf("failed to read ip packet %s: %v", f.Name(), err)
		}
		defer handle.Close()

		// Get Packets in each pcap file
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for pkt := range packetSource.Packets() {
			ipPackets = append(ipPackets, pkt)
		}
	}

	return ipPackets
}

// Load IP Packets

// Read & Load generated pcap files
func loadPackets(t *testing.T) ([]gopacket.Packet, []slayers.SCION) {

	ipPackets := loadIpPackets(t)

	//scionPackets := loadScionPackets(t)

	scionPackets := loadScionPacketsFromBinDir(t, "packets/scion_packets")

	return ipPackets, scionPackets
}

// Comparison Functions
func CompareIPPackets(pkt1, pkt2 gopacket.Packet) bool {

	if pkt1 == nil || pkt2 == nil {
		return false
	}

	ip1 := pkt1.Layer(layers.LayerTypeIPv4)
	ip2 := pkt2.Layer(layers.LayerTypeIPv4)

	if ip1 == nil || ip2 == nil {
		return false
	}

	ipLayer1 := ip1.(*layers.IPv4)
	ipLayer2 := ip2.(*layers.IPv4)

	//Compare IP header Fields
	if !ipLayer1.SrcIP.Equal(ipLayer2.SrcIP) ||
		!ipLayer1.DstIP.Equal(ipLayer2.DstIP) ||
		ipLayer1.Protocol != ipLayer2.Protocol {
		return false
	}

	//Compare payload
	if !bytes.Equal(pkt1.ApplicationLayer().Payload(), pkt2.ApplicationLayer().Payload()) {
		return false
	}

	return true
}

func CompareSCIONPackets(pkt1, pkt2 slayers.SCION) bool {

	return pkt1.SrcIA == pkt2.SrcIA &&
		pkt1.DstIA == pkt2.DstIA &&
		pkt1.NextHdr == pkt2.NextHdr &&
		bytes.Equal(pkt1.RawSrcAddr, pkt2.RawSrcAddr) &&
		bytes.Equal(pkt1.RawDstAddr, pkt2.RawDstAddr) &&
		bytes.Equal(pkt1.Payload, pkt2.Payload)
}

// Translate Functions

func translateIPtoSCION(gopacket.Packet) slayers.SCION {
	var scion slayers.SCION

	return scion
}

func translateSCIONtoIP(slayers.SCION) gopacket.Packet {

	return nil
}

// Test IP to Scion Translation
func TestIPtoSCIONTranslation(t *testing.T) {

	createPackets(t)

	//Get all IP Packets
	ipPackets, scionPackets := loadPackets(t)

	if len(ipPackets) != len(scionPackets) {
		t.Fatalf("mismatched number of IP (%d) and SCION (%d) packets",
			len(ipPackets), len(scionPackets))
	}

	//Iterate through each IP Packets
	for i, ipPkt := range ipPackets {

		//Pass IP Packet through translation
		got := translateIPtoSCION(ipPkt)

		//Get target Scion Package
		want := scionPackets[i]

		//Compare Translated SCION Packet with Generated SCION Packet
		CompareSCIONPackets(got, want)
	}
}

// Test Scion to IP Translation
func TestSCIONtoIPTranslation(t *testing.T) {

	createPackets(t)

	//Get all IP Packets
	ipPackets, scionPackets := loadPackets(t)

	if len(scionPackets) != len(ipPackets) {
		t.Fatalf("mismatched number of IP (%d) and SCION (%d) packets",
			len(ipPackets), len(scionPackets))
	}

	//Iterate through each IP Packets
	for i, scionPkt := range scionPackets {

		//Pass IP Packet through translation
		got := translateSCIONtoIP(scionPkt)

		//Get target Scion Package
		want := ipPackets[i]

		//Compare Translated SCION Packet with Generated SCION Packet
		CompareIPPackets(got, want)

	}

}

// Test IP to Scion and Back to IP Translation
func TestIPtoSCIONtoIPTranslation(t *testing.T) {

	createPackets(t)

	//Get all IP Packets
	ipPackets, scionPackets := loadPackets(t)

	if len(scionPackets) != len(ipPackets) {
		t.Fatalf("mismatched number of IP (%d) and SCION (%d) packets",
			len(ipPackets), len(scionPackets))
	}

	for i, ipPkt := range ipPackets {
		//Pass IP Packet through translation
		gotScion := translateIPtoSCION(ipPkt)
		//Pass Scion Packet through translation
		gotIP := translateSCIONtoIP(gotScion)

		wantIP := ipPackets[i]

		//Compare Ip Packets
		CompareIPPackets(gotIP, wantIP)
	}

}

// Test Scion to IP and back to Scion Translation
func TestSCIONtoIPtoSCIONTranslation(t *testing.T) {

	createPackets(t)

	//Get all IP Packets
	ipPackets, scionPackets := loadPackets(t)

	if len(scionPackets) != len(ipPackets) {
		t.Fatalf("mismatched number of IP (%d) and SCION (%d) packets",
			len(ipPackets), len(scionPackets))
	}

	for i, scionPkt := range scionPackets {

		//Pass Scion Packet through translation
		gotIP := translateSCIONtoIP(scionPkt)

		//Pass IP Packet through translation
		gotScion := translateIPtoSCION(gotIP)

		wantScion := scionPackets[i]

		//Compare Scion Packets
		CompareSCIONPackets(gotScion, wantScion)

	}
}
