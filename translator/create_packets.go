package translator

//ToDo: Add IP Packet creation so .py script becomes redudant!

import (
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket"
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

func GenerateScionPackets() {

	os.MkdirAll("packets/scion_packets", 0755)

	createSCIONPacket("packets/scion_packets/test1.bin", 1, 1, 0xff000111, 0xff000112, "192.0.2.1", "192.0.2.2")
}
