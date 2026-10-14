package addr_translation

import (
	"net"
	"testing"
)

func TestS2IPMatchesPythonExamples(t *testing.T) {
	tests := []struct {
		name        string
		isdASN      string
		localPrefix string
		subnet      string
		iface       string
		subnetBits  uint
		want        string
	}{
		{
			name:        "ISD1 ASN64513 interface 0",
			isdASN:      "1-64513",
			localPrefix: "0",
			subnet:      "0",
			iface:       "0",
			subnetBits:  8,
			want:        "fc00:10fc:100::",
		},
		{
			name:        "ISD1 ASN64513 interface 1",
			isdASN:      "1-64513",
			localPrefix: "0",
			subnet:      "0",
			iface:       "1",
			subnetBits:  8,
			want:        "fc00:10fc:100::1",
		},
		{
			name:        "ISD1 ASN64513 interface ff00:1",
			isdASN:      "1-64513",
			localPrefix: "0",
			subnet:      "0",
			iface:       "ff00:1",
			subnetBits:  8,
			want:        "fc00:10fc:100::ff00:1",
		},
		{
			name:        "IPv4 mapped host",
			isdASN:      "1-64513",
			localPrefix: "0",
			subnet:      "0",
			iface:       "141.44.25.150",
			subnetBits:  8,
			want:        "fc00:10fc:100::ffff:8d2c:1996",
		},
		{
			name:        "SCION style ASN 2:0:4a",
			isdASN:      "71-2:0:4a",
			localPrefix: "0",
			subnet:      "0",
			iface:       "141.44.25.150",
			subnetBits:  8,
			want:        "fc04:7800:4a00::ffff:8d2c:1996",
		},
		{
			name:        "local prefix and subnet",
			isdASN:      "1-64513",
			localPrefix: "12",
			subnet:      "34",
			iface:       "1",
			subnetBits:  8,
			want:        "fc00:10fc:100:1234::1",
		},
		{
			name:        "different ISD and ASN",
			isdASN:      "2-1000",
			localPrefix: "0",
			subnet:      "0",
			iface:       "1",
			subnetBits:  8,
			want:        "fc00:2003:e800::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := S2IP(tt.isdASN, tt.localPrefix, tt.subnet, tt.iface, tt.subnetBits)
			if err != nil {
				t.Fatalf("S2IP() error = %v", err)
			}
			if got.String() != tt.want {
				t.Fatalf("S2IP() = %s, want %s", got.String(), tt.want)
			}
		})
	}
}

func TestIP2SMatchesPythonExamples(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		subnetBits uint
		want       string
	}{
		{
			name:       "interface 0",
			input:      "fc00:10fc:100::",
			subnetBits: 8,
			want:       "1-64513 0 0 0",
		},
		{
			name:       "interface 1",
			input:      "fc00:10fc:100::1",
			subnetBits: 8,
			want:       "1-64513 0 0 1",
		},
		{
			name:       "interface ff00:1",
			input:      "fc00:10fc:100::ff00:1",
			subnetBits: 8,
			want:       "1-64513 0 0 ff00:1",
		},
		{
			name:       "IPv4 mapped host",
			input:      "fc00:10fc:100::ffff:8d2c:1996",
			subnetBits: 8,
			want:       "1-64513 0 0 141.44.25.150",
		},
		{
			name:       "SCION style ASN 2:0:4a",
			input:      "fc04:7800:4a00::ffff:8d2c:1996",
			subnetBits: 8,
			want:       "71-2:0:4a 0 0 141.44.25.150",
		},
		{
			name:       "local prefix and subnet",
			input:      "fc00:10fc:100:1234::1",
			subnetBits: 8,
			want:       "1-64513 12 34 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IP2S(net.ParseIP(tt.input), tt.subnetBits)
			if err != nil {
				t.Fatalf("IP2S() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("IP2S() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScionToIPOldAPI(t *testing.T) {
	tests := []struct {
		name       string
		isd        int
		asn        uint64
		localPref  uint64
		subnet     uint64
		iface      net.IP
		subnetBits int
		want       string
	}{
		{
			name:       "ISD1 ASN64513 interface 0",
			isd:        1,
			asn:        64513,
			localPref:  0,
			subnet:     0,
			iface:      net.ParseIP("::"),
			subnetBits: 8,
			want:       "fc00:10fc:100::",
		},
		{
			name:       "ISD1 ASN64513 interface 1",
			isd:        1,
			asn:        64513,
			localPref:  0,
			subnet:     0,
			iface:      net.ParseIP("::1"),
			subnetBits: 8,
			want:       "fc00:10fc:100::1",
		},
		{
			name:       "IPv4 mapped host",
			isd:        71,
			asn:        0x2_0000_004a,
			localPref:  0,
			subnet:     0,
			iface:      net.ParseIP("141.44.25.150"),
			subnetBits: 8,
			want:       "fc04:7800:4a00::ffff:8d2c:1996",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ScionToIP(
				tt.isd,
				ASN{Value: tt.asn},
				tt.localPref,
				tt.subnet,
				tt.iface,
				tt.subnetBits,
			)
			if err != nil {
				t.Fatalf("ScionToIP() error = %v", err)
			}
			if got.String() != tt.want {
				t.Fatalf("ScionToIP() = %s, want %s", got.String(), tt.want)
			}
		})
	}
}

func TestUnmapIPv6ForTranslator(t *testing.T) {
	isd, asn, localPrefix, subnet, host, hostIsIPv4, err :=
		UnmapIPv6(net.ParseIP("fc04:7800:4a00::ffff:8d2c:1996"), 8)

	if err != nil {
		t.Fatalf("UnmapIPv6() error = %v", err)
	}
	if isd != 71 {
		t.Fatalf("ISD = %d, want 71", isd)
	}
	if asn != 0x2_0000_004a {
		t.Fatalf("ASN = %#x, want %#x", asn, uint64(0x2_0000_004a))
	}
	if localPrefix != 0 || subnet != 0 {
		t.Fatalf("localPrefix/subnet = %x/%x, want 0/0", localPrefix, subnet)
	}
	if !hostIsIPv4 {
		t.Fatalf("hostIsIPv4 = false, want true")
	}
	if got := host.To4().String(); got != "141.44.25.150" {
		t.Fatalf("host = %s, want 141.44.25.150", got)
	}
}

func TestRoundTripPythonStyle(t *testing.T) {
	inputs := []string{
		"1-64513 0 0 0",
		"1-64513 0 0 1",
		"1-64513 0 0 ff00:1",
		"1-64513 0 0 141.44.25.150",
		"71-2:0:4a 0 0 141.44.25.150",
		"1-64513 12 34 1",
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			parts := stringsFields(input)
			ip, err := S2IP(parts[0], parts[1], parts[2], parts[3], 8)
			if err != nil {
				t.Fatalf("S2IP() error = %v", err)
			}

			got, err := IP2S(ip, 8)
			if err != nil {
				t.Fatalf("IP2S() error = %v", err)
			}

			if got != input {
				t.Fatalf("round trip = %q, want %q", got, input)
			}
		})
	}
}

func stringsFields(s string) []string {
	var out []string
	start := -1

	for i, r := range s {
		if r == ' ' || r == '\t' || r == '\n' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

func TestInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		fn   func() error
	}{
		{
			name: "IPv4 with nonzero prefix is invalid",
			fn: func() error {
				_, err := S2IP("1-64513", "1", "0", "141.44.25.150", 8)
				return err
			},
		},
		{
			name: "subnetBits too large",
			fn: func() error {
				_, err := S2IP("1-64513", "0", "0", "1", 25)
				return err
			},
		},
		{
			name: "ASN cannot be encoded",
			fn: func() error {
				_, err := S2IP("1-999999999", "0", "0", "1", 8)
				return err
			},
		},
		{
			name: "full IPv6 iface rejected by old API",
			fn: func() error {
				_, err := ScionToIP(1, ASN{Value: 64513}, 0, 0, net.ParseIP("2001:db8::1"), 8)
				return err
			},
		},
		{
			name: "non mapped IPv6 rejected",
			fn: func() error {
				_, err := IP2S(net.ParseIP("2001:db8::1"), 8)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}
