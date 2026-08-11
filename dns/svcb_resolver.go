/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2026 SCIONtra / WireGuard Project
 */

package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// SVCBTargetInfo represents a parsed SVCB (Type 64) or HTTPS (Type 65) record.
type SVCBTargetInfo struct {
	Priority  uint16   `json:"priority"`
	Target    string   `json:"target"`
	Port      uint16   `json:"port"`
	ALPN      []string `json:"alpn"`
	IPv4Hints []net.IP `json:"ipv4_hints"`
	IPv6Hints []net.IP `json:"ipv6_hints"`
	ScionHint string   `json:"scion_hint"`
}

// Resolver handles DNS queries for SVCB/HTTPS records.
type Resolver struct {
	DNSServer string
	Timeout   time.Duration
}

// NewResolver initializes a DNS resolver targeting the given DNS server address (e.g., "8.8.8.8:53").
func NewResolver(dnsServer string) *Resolver {
	if dnsServer == "" {
		dnsServer = "8.8.8.8:53"
	} else if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}
	return &Resolver{
		DNSServer: dnsServer,
		Timeout:   3 * time.Second,
	}
}

// QuerySVCB queries the DNS server for SVCB (Type 64) or HTTPS (Type 65) records for the domain.
func (r *Resolver) QuerySVCB(ctx context.Context, domain string) ([]SVCBTargetInfo, error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	c := new(dns.Client)
	c.Timeout = r.Timeout

	// Try HTTPS (Type 65) first, then SVCB (Type 64)
	targets, err := r.queryRRType(c, domain, dns.TypeHTTPS)
	if err != nil || len(targets) == 0 {
		targets, err = r.queryRRType(c, domain, dns.TypeSVCB)
	}

	if err != nil {
		return nil, err
	}

	// Sort targets by Priority (lowest priority number = highest preference)
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Priority < targets[j].Priority
	})

	return targets, nil
}

func (r *Resolver) queryRRType(c *dns.Client, domain string, qtype uint16) ([]SVCBTargetInfo, error) {
	m := new(dns.Msg)
	m.SetQuestion(domain, qtype)
	m.RecursionDesired = true

	rrs, _, err := c.Exchange(m, r.DNSServer)
	if err != nil {
		return nil, fmt.Errorf("dns exchange failed: %w", err)
	}

	var results []SVCBTargetInfo

	for _, ans := range rrs.Answer {
		switch rr := ans.(type) {
		case *dns.HTTPS:
			info := parseSVCBValue(rr.Priority, rr.Target, rr.Value)
			results = append(results, info)
		case *dns.SVCB:
			info := parseSVCBValue(rr.Priority, rr.Target, rr.Value)
			results = append(results, info)
		}
	}

	return results, nil
}

func parseSVCBValue(priority uint16, target string, values []dns.SVCBKeyValue) SVCBTargetInfo {
	info := SVCBTargetInfo{
		Priority: priority,
		Target:   strings.TrimSuffix(target, "."),
		Port:     443, // Default HTTPS port
	}

	for _, kv := range values {
		switch v := kv.(type) {
		case *dns.SVCBPort:
			info.Port = v.Port
		case *dns.SVCBAlpn:
			info.ALPN = v.Alpn
		case *dns.SVCBIPv4Hint:
			info.IPv4Hints = v.Hint
		case *dns.SVCBIPv6Hint:
			info.IPv6Hints = v.Hint
		case *dns.SVCBLocal:
			// Check for custom SCION keys or raw text parameters
			valStr := v.String()
			if strings.Contains(strings.ToLower(valStr), "scion") {
				info.ScionHint = valStr
			}
		}
	}

	return info
}
