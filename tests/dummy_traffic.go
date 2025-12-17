package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	i := flag.String("i", "", "Interface to send packets on")
	count := flag.Int("cnt", 1, "Number of packets to send")
	payload := flag.String("p", "dummy", "Payload string")

	flag.Parse()

	if *i == "" {
		log.Fatal("You must specify -i")
	}

	// Open interface
	handle, err := pcap.OpenLive(*i, 65536, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open interface: %v", err)
	}
	defer handle.Close()

	// Dummy MAC and IPs (customize if needed)
	/* srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	dstMAC, _ := net.ParseMAC("02:00:00:00:00:02") */
	srcIP := net.IPv4(10, 0, 0, 1)
	dstIP := net.IPv4(10, 0, 0, 2)

	for i := 0; i < *count; i++ {
		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		/* eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		} */
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: layers.IPProtocolUDP,
		}
		udp := &layers.UDP{
			SrcPort: 51820,
			DstPort: 51820,
		}
		udp.SetNetworkLayerForChecksum(ip)

		payloadLayer := gopacket.Payload([]byte(*payload))

		err = gopacket.SerializeLayers(buffer, opts,
			//eth,
			ip,
			udp,
			payloadLayer,
		)
		if err != nil {
			log.Fatalf("Serialization error: %v", err)
		}

		err = handle.WritePacketData(buffer.Bytes())
		if err != nil {
			log.Printf("Error sending packet %d: %v", i+1, err)
		} else {
			fmt.Printf("Sent packet %d with payload: %q\n", i+1, *payload)
		}

		time.Sleep(100 * time.Millisecond)
	}
}
