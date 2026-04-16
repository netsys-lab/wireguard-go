//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"net"

	"github.com/scionproto/scion/wireguard-go/translator/addr_translation"
)

func main() {
	// AS64513 = ISD=1, ASN=64513
	asn64513, _ := addr_translation.ParseASN("64513")
	ip64513, err := addr_translation.ScionToIP(1, asn64513, 0, 0, net.ParseIP("::"), 8)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("AS64513 (interface=0): %s\n", ip64513)

	ip64513_h1, err := addr_translation.ScionToIP(1, asn64513, 0, 0, net.ParseIP("::1"), 8)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("AS64513 (interface=1): %s\n", ip64513_h1)

	// AS64514 = ISD=1, ASN=64514
	asn64514, _ := addr_translation.ParseASN("64514")
	ip64514, err := addr_translation.ScionToIP(1, asn64514, 0, 0, net.ParseIP("::"), 8)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("AS64514 (interface=0): %s\n", ip64514)

	ip64514_h1, err := addr_translation.ScionToIP(1, asn64514, 0, 0, net.ParseIP("::1"), 8)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("AS64514 (interface=1): %s\n", ip64514_h1)
}
