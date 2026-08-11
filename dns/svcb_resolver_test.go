/* SPDX-License-Identifier: Apache-2.0
 * Copyright © 2026 SCIONtra / WireGuard Project
 */

package dns

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSVCBResolverStructure(t *testing.T) {
	resolver := NewResolver("1.1.1.1:53")
	assert.Equal(t, "1.1.1.1:53", resolver.DNSServer)
	assert.Equal(t, 3*time.Second, resolver.Timeout)
}

func TestQuerySVCBPublicDomain(t *testing.T) {
	// Query a domain known to publish HTTPS/SVCB records (e.g., cloudflare.com or crypto.cloudflare.com)
	resolver := NewResolver("1.1.1.1:53")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	targets, err := resolver.QuerySVCB(ctx, "cloudflare.com")
	if err != nil {
		t.Logf("DNS query failed (network may be unavailable in test env): %v", err)
		return
	}

	t.Logf("Discovered %d SVCB/HTTPS targets for cloudflare.com", len(targets))
	for i, target := range targets {
		t.Logf("  [%d] Priority=%d, Target=%s, Port=%d, ALPN=%v",
			i, target.Priority, target.Target, target.Port, target.ALPN)
	}
}
