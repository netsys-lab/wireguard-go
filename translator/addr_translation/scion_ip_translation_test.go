package addr_translation

import (
	"net"
	"testing"
)

func TestScionToIP(t *testing.T) {
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
			name:       "ISD1-ASN64513 interface 0",
			isd:        1,
			asn:        64513,
			localPref:  0,
			subnet:     0,
			iface:      net.ParseIP("::0"),
			subnetBits: 8,
			want:       "fc00:10fc:100::",
		},
		{
			name:       "ISD1-ASN64513 interface 1",
			isd:        1,
			asn:        64513,
			localPref:  0,
			subnet:     0,
			iface:      net.ParseIP("::1"),
			subnetBits: 8,
			want:       "fc00:10fc:100::1",
		},
		{
			name:       "ISD1-ASN64513 interface ff00:1",
			isd:        1,
			asn:        64513,
			localPref:  0,
			subnet:     0,
			iface:      net.ParseIP("::ff00:1"),
			subnetBits: 8,
			want:       "fc00:10fc:100::ff00:1",
		},
		{
			name:       "Different ISD and ASN",
			isd:        2,
			asn:        1000,
			localPref:  0,
			subnet:     0,
			iface:      net.ParseIP("::1"),
			subnetBits: 8,
			want:       "fc00:2003:e800::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asn := ASN{Value: tt.asn}
			got, err := ScionToIP(tt.isd, asn, tt.localPref, tt.subnet, tt.iface, tt.subnetBits)
			if err != nil {
				t.Fatalf("ScionToIP() error = %v", err)
			}
			if got.String() != tt.want {
				t.Errorf("ScionToIP() = %v, want %v", got.String(), tt.want)
			}
		})
	}
}

func TestIPToScion(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		subnetBits int
		wantISD    int
		wantASN    uint64
	}{
		{
			name:       "ISD1-ASN64513 interface 0",
			input:      "fc00:10fc:100::",
			subnetBits: 8,
			wantISD:    1,
			wantASN:    64513,
		},
		{
			name:       "ISD1-ASN64513 interface 1",
			input:      "fc00:10fc:100::1",
			subnetBits: 8,
			wantISD:    1,
			wantASN:    64513,
		},
		{
			name:       "ISD1-ASN64513 interface ff00:1",
			input:      "fc00:10fc:100::ff00:1",
			subnetBits: 8,
			wantISD:    1,
			wantASN:    64513,
		},
		{
			name:       "Different ISD and ASN",
			input:      "fc00:2003:e800::1",
			subnetBits: 8,
			wantISD:    2,
			wantASN:    1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputIP := net.ParseIP(tt.input)
			gotISD, gotASN, _, _, _, err := IPToScion(inputIP, tt.subnetBits)
			if err != nil {
				t.Fatalf("IPToScion() error = %v", err)
			}
			if gotISD != tt.wantISD {
				t.Errorf("IPToScion() ISD = %d, want %d", gotISD, tt.wantISD)
			}
			if gotASN.Value != tt.wantASN {
				t.Errorf("IPToScion() ASN = %d, want %d", gotASN.Value, tt.wantASN)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	testCases := []struct {
		isd   int
		asn   uint64
		iface string
	}{
		{isd: 1, asn: 64513, iface: "::0"},
		{isd: 1, asn: 64513, iface: "::1"},
		{isd: 1, asn: 64513, iface: "::ff00:1"},
		{isd: 2, asn: 1000, iface: "::1"},
		{isd: 1, asn: 1, iface: "::1"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			// Encode
			asn := ASN{Value: tc.asn}
			ip, err := ScionToIP(tc.isd, asn, 0, 0, net.ParseIP(tc.iface), 8)
			if err != nil {
				t.Fatalf("ScionToIP() error = %v", err)
			}

			// Decode
			gotISD, gotASN, _, _, _, err := IPToScion(ip, 8)
			if err != nil {
				t.Fatalf("IPToScion() error = %v", err)
			}

			// Verify
			if gotISD != tc.isd {
				t.Errorf("RoundTrip ISD: got %d, want %d", gotISD, tc.isd)
			}
			if gotASN.Value != tc.asn {
				t.Errorf("RoundTrip ASN: got %d, want %d", gotASN.Value, tc.asn)
			}
		})
	}
}

func TestASNEncoding(t *testing.T) {
	tests := []struct {
		asn     uint64
		wantEnc uint64
	}{
		{0, 0},
		{1, 1},
		{1000, 1000},
		{64513, 64513},
		{0x1FFFF, 0x1FFFF},
		{0x200000000, (1 << 19) | 0},       // Large ASN starts encoding differently
		{0x20007FFFF, (1 << 19) | 0x7FFFF}, // Max large ASN
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			asn := ASN{Value: tt.asn}
			var encoded uint64
			if asn.Value < (1 << 19) {
				encoded = asn.Value
			} else if asn.Value >= 0x200000000 && asn.Value <= 0x20007ffff {
				encoded = (1 << 19) | (asn.Value & 0x7ffff)
			}
			if encoded != tt.wantEnc {
				t.Errorf("ASN %d encoding = %d, want %d", tt.asn, encoded, tt.wantEnc)
			}
		})
	}
}

func TestInvalidInput(t *testing.T) {
	tests := []struct {
		name       string
		isd        int
		asn        uint64
		iface      net.IP
		subnetBits int
		wantErr    bool
	}{
		{
			name:       "ISD out of range",
			isd:        -1,
			asn:        64513,
			iface:      net.ParseIP("::1"),
			subnetBits: 8,
			wantErr:    true,
		},
		{
			name:       "ISD too large",
			isd:        1 << 12,
			asn:        64513,
			iface:      net.ParseIP("::1"),
			subnetBits: 8,
			wantErr:    true,
		},
		{
			name:       "ASN cannot be encoded",
			isd:        1,
			asn:        0x300000000, // Invalid range
			iface:      net.ParseIP("::1"),
			subnetBits: 8,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asn := ASN{Value: tt.asn}
			_, err := ScionToIP(tt.isd, asn, 0, 0, tt.iface, tt.subnetBits)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScionToIP() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
