package utils

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ProcessPacket(pkt []byte, IsIPv6 bool) (out []byte, err error) {

	return pkt, nil
}

func DeserializePacket() {

}

func SerializePacket() {

}

// TODO: Move to new file?
func ReadPacket(pkt []byte, IsIPv6 bool) (out []byte, err error) {

	//Is it IPv6?
	if IsIPv6 {
		//create new gopacket
		p := gopacket.NewPacket(pkt, layers.LayerTypeIPv6, gopacket.Default)
		// IPv6 schicht holen
		ip6Layer := p.Layer(layers.LayerTypeIPv6)
		if ip6Layer == nil {
			return pkt, fmt.Errorf("no ipv6 layer")
		}
		ip6 := ip6Layer.(*layers.IPv6)

		//UDP schicht holen
		udpLayer := p.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return pkt, nil // Kein UDPLayer
		}
		udp := udpLayer.(*layers.UDP)

		//Payload kopieren und ersetzten
		newPayload := make([]byte, len(udp.Payload))
		copy(newPayload, udp.Payload)
		if len(newPayload) > 0 {
			//newPayload[0] ^= 0xFF
			payloadStr := string(udp.Payload)
			// fmt.Println("Received payload:", payloadStr)
			newPayloadStr := payloadStr + " [modified]"
			newPayload = []byte(newPayloadStr)

			udp.Payload = newPayload
		}

		//Or make new own Payload - Why does this not work?
		//udp.Payload = []byte("MODIFIED")

		//Wichtig damit Checksum richtig berechnet wird
		udp.SetNetworkLayerForChecksum(ip6)

		//Serialisiert IPv6 + UDP + Payload
		//Fixlenghs setzt längenfelde
		//ComputeChecksums berechnet Checksum neu
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		err = gopacket.SerializeLayers(buf, opts, ip6, udp, gopacket.Payload(newPayload))
		if err != nil {
			return nil, err
		}

		out = buf.Bytes()

	} else {
		p := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)
		ip4Layer := p.Layer(layers.LayerTypeIPv4)
		if ip4Layer == nil {
			return pkt, fmt.Errorf("no ipv4 layer")
		}
		ip4 := ip4Layer.(*layers.IPv4)
		udpLayer := p.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return pkt, nil
		}
		udp := udpLayer.(*layers.UDP)

		newPayload := make([]byte, len(udp.Payload))
		copy(newPayload, udp.Payload)
		if len(newPayload) > 0 {
			newPayload[0] ^= 0xFF
		}

		// set checksum network layer
		udp.SetNetworkLayerForChecksum(ip4)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		err = gopacket.SerializeLayers(buf, opts, ip4, udp, gopacket.Payload(newPayload))
		if err != nil {
			return nil, err
		}

		out = buf.Bytes()
	}

	//Wenn out größer als cap(pkt), caller muss umziehen
	if len(out) > cap(pkt) {
		return out, fmt.Errorf("new packet exceeds buffer")
	}
	// sonst kopiere zurück in pkt (in-place)
	copy(pkt[:len(out)], out)
	return pkt[:len(out)], nil
}
