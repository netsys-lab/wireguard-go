package header_parsing

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"golang.zx2c4.com/wireguard/scionlog"
)

const (
	// DefaultFlowPathTTL is the idle timeout after which inactive flows are pruned.
	DefaultFlowPathTTL = 2 * time.Minute

	// DefaultSoftExpiryWindow defines how many seconds before path expiration
	// the cache reports a miss to trigger a seamless background soft-refresh.
	DefaultSoftExpiryWindow = 30 * time.Second

	// DefaultCleanupInterval is the frequency of background idle flow sweeps.
	DefaultCleanupInterval = 30 * time.Second
)

// FlowKey represents the 5-tuple of an inner IP packet traversing the tunnel.
// Since all fields are value types, FlowKey is strictly comparable and zero-alloc.
type FlowKey struct {
	SrcAddr netip.Addr
	DstAddr netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s:%d->%s:%d (proto=%d)", k.SrcAddr, k.SrcPort, k.DstAddr, k.DstPort, k.Proto)
}

// ExtractFlowKey parses the inner packet headers using zero allocations to derive the 5-tuple.
// Returns false if the packet is truncated, not IPv6, or contains unhandled extension headers.
func ExtractFlowKey(pktData []byte) (FlowKey, bool) {
	if len(pktData) < 40 || pktData[0]>>4 != 6 {
		return FlowKey{}, false
	}

	srcAddr := netip.AddrFrom16([16]byte(pktData[8:24]))
	dstAddr := netip.AddrFrom16([16]byte(pktData[24:40]))
	proto := pktData[6]

	var srcPort, dstPort uint16
	switch proto {
	case 6, 17: // TCP, UDP
		if len(pktData) < 44 {
			return FlowKey{}, false
		}
		srcPort = binary.BigEndian.Uint16(pktData[40:42])
		dstPort = binary.BigEndian.Uint16(pktData[42:44])

	case 58: // ICMPv6
		if len(pktData) >= 48 {
			icmpType := pktData[40]
			if icmpType == 128 || icmpType == 129 { // Echo Request / Reply
				ident := binary.BigEndian.Uint16(pktData[44:46])
				srcPort = ident
				dstPort = ident
			}
		}

	default:
		// Unknown or extension header: fallback to non-cached path
		return FlowKey{}, false
	}

	return FlowKey{
		SrcAddr: srcAddr,
		DstAddr: dstAddr,
		SrcPort: srcPort,
		DstPort: dstPort,
		Proto:   proto,
	}, true
}

// CachedFlowPath encapsulates a pinned SCION path and its metadata for a specific flow.
type CachedFlowPath struct {
	Path        path.Path
	NextHop     *net.UDPAddr
	Expiry      time.Time
	Fingerprint string
	SrcIA       addr.IA
	DstIA       addr.IA
	WireTuple   SCIONTuple

	lastSeen int64 // unix nano timestamp, updated atomically
}

// LastSeen returns the timestamp when this flow was last accessed.
func (c *CachedFlowPath) LastSeen() time.Time {
	return time.Unix(0, atomic.LoadInt64(&c.lastSeen))
}

// MatchesSCIONTuple checks if this cached flow corresponds to a quoted tuple from an SCMP error.
func (c *CachedFlowPath) MatchesSCIONTuple(qt *SCIONTuple) bool {
	if qt == nil {
		return false
	}
	if qt.Protocol != 0 && c.WireTuple.Protocol != qt.Protocol {
		return false
	}
	if qt.SrcIA != 0 && c.WireTuple.SrcIA != qt.SrcIA {
		return false
	}
	if qt.DstIA != 0 && c.WireTuple.DstIA != qt.DstIA {
		return false
	}
	if qt.SrcHost.IsValid() && c.WireTuple.SrcHost.IsValid() && c.WireTuple.SrcHost != qt.SrcHost {
		return false
	}
	if qt.DstHost.IsValid() && c.WireTuple.DstHost.IsValid() && c.WireTuple.DstHost != qt.DstHost {
		return false
	}
	if qt.SrcPort != 0 && c.WireTuple.SrcPort != 0 && c.WireTuple.SrcPort != qt.SrcPort {
		return false
	}
	if qt.DstPort != 0 && c.WireTuple.DstPort != 0 && c.WireTuple.DstPort != qt.DstPort {
		return false
	}
	return true
}

// FlowPathCache is a high-performance, read-lockfree cache that maps inner packet 5-tuples
// to pinned SCION paths, eliminating per-packet PathPool lookups and mutex contention.
type FlowPathCache struct {
	flows            sync.Map // FlowKey -> *CachedFlowPath
	log              *scionlog.Logger
	flowTTL          time.Duration
	softExpiryWindow time.Duration

	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewFlowPathCache initializes a new FlowPathCache and starts background cleanup.
func NewFlowPathCache(log *scionlog.Logger) *FlowPathCache {
	if log == nil {
		log = scionlog.NewLogger(func(string, ...any) {}, func(string, ...any) {})
	}

	c := &FlowPathCache{
		log:              log,
		flowTTL:          DefaultFlowPathTTL,
		softExpiryWindow: DefaultSoftExpiryWindow,
		stopCh:           make(chan struct{}),
	}

	go c.cleanupLoop()
	return c
}

// SetFlowTTL configures the flow idle TTL.
func (c *FlowPathCache) SetFlowTTL(ttl time.Duration) {
	if ttl > 0 {
		c.flowTTL = ttl
	}
}

// SetSoftExpiryWindow configures the pro-active soft-refresh window before expiration.
func (c *FlowPathCache) SetSoftExpiryWindow(window time.Duration) {
	if window >= 0 {
		c.softExpiryWindow = window
	}
}

// Get performs an O(1) lock-free lookup for a cached path.
// Returns:
//   entry: the cached path entry (if found and not hard-expired)
//   hit: true if a valid entry was found
//   needsRefresh: true if the entry is within the soft-expiry window (<= 30s remaining)
func (c *FlowPathCache) Get(key FlowKey) (entry *CachedFlowPath, hit bool, needsRefresh bool) {
	val, ok := c.flows.Load(key)
	if !ok {
		return nil, false, false
	}

	entry = val.(*CachedFlowPath)
	now := time.Now()

	// Hard expiration: Hop-MACs are expired; drop entry immediately
	if !entry.Expiry.IsZero() && now.After(entry.Expiry) {
		c.flows.Delete(key)
		if c.log.IsDebug() {
			c.log.Infof(scionlog.ComponentPath, "[FLOW-CACHE] expired flow=%s expiry=%s", key, entry.Expiry.Format(time.RFC3339))
		}
		return nil, false, false
	}

	atomic.StoreInt64(&entry.lastSeen, now.UnixNano())

	// Soft expiration: Pro-active refresh window reached
	if !entry.Expiry.IsZero() && c.softExpiryWindow > 0 && now.After(entry.Expiry.Add(-c.softExpiryWindow)) {
		if c.log.IsDebug() {
			c.log.Infof(scionlog.ComponentPath, "[FLOW-CACHE] soft-expiry flow=%s expiry=%s remaining=%v",
				key, entry.Expiry.Format(time.RFC3339), time.Until(entry.Expiry))
		}
		return entry, true, true
	}

	return entry, true, false
}

// Put stores or updates a pinned path for the specified flow key.
func (c *FlowPathCache) Put(key FlowKey, p path.Path, srcIA, dstIA addr.IA, wireTuple SCIONTuple) *CachedFlowPath {
	var expiry time.Time
	var fingerprint string

	meta := p.Metadata()
	if meta != nil {
		expiry = meta.Expiry
		fingerprint = snet.Fingerprint(meta.Interfaces).String()
	} else if srcIA == dstIA {
		// Same-AS traffic (empty path): safe long-lived default expiry (24 hours)
		expiry = time.Now().Add(24 * time.Hour)
		fingerprint = fmt.Sprintf("same-as-%s", srcIA)
	} else {
		expiry = time.Now().Add(2 * time.Minute)
		fingerprint = fmt.Sprintf("no-meta-%s-%s", srcIA, dstIA)
	}

	var nextHop *net.UDPAddr
	if nh := p.UnderlayNextHop(); nh != nil {
		nextHop = &net.UDPAddr{
			IP:   nh.IP,
			Port: nh.Port,
			Zone: nh.Zone,
		}
	}

	entry := &CachedFlowPath{
		Path:        p,
		NextHop:     nextHop,
		Expiry:      expiry,
		Fingerprint: fingerprint,
		SrcIA:       srcIA,
		DstIA:       dstIA,
		WireTuple:   wireTuple,
		lastSeen:    time.Now().UnixNano(),
	}

	c.flows.Store(key, entry)
	if c.log.IsDebug() {
		c.log.Infof(scionlog.ComponentPath, "[FLOW-CACHE] store flow=%s fp=%s srcIA=%s dstIA=%s expiry=%s nextHop=%v",
			key, fingerprint, srcIA, dstIA, expiry.Format(time.RFC3339), nextHop)
	}

	return entry
}

// Invalidate removes a specific flow from the cache.
func (c *FlowPathCache) Invalidate(key FlowKey) bool {
	_, loaded := c.flows.LoadAndDelete(key)
	if loaded && c.log.IsDebug() {
		c.log.Infof(scionlog.ComponentPath, "[FLOW-CACHE] invalidated flow=%s", key)
	}
	return loaded
}

// InvalidateBySCIONTuple invalidates any cached flow matching the quoted SCION wire tuple.
// Used for immediate reactive failover when an inbound SCMP error arrives.
func (c *FlowPathCache) InvalidateBySCIONTuple(qt *SCIONTuple) int {
	if qt == nil {
		return 0
	}

	count := 0
	c.flows.Range(func(k, v any) bool {
		entry := v.(*CachedFlowPath)
		if entry.MatchesSCIONTuple(qt) {
			c.flows.Delete(k)
			count++
			if c.log.IsDebug() {
				c.log.Infof(scionlog.ComponentPath, "[FLOW-CACHE] scmp-invalidated flow=%v reason=scmp-error qt=%+v", k, *qt)
			}
		}
		return true
	})

	return count
}

// InvalidateByIA removes all cached flows between the specified ISD-AS pair.
func (c *FlowPathCache) InvalidateByIA(srcIA, dstIA addr.IA) int {
	count := 0
	c.flows.Range(func(k, v any) bool {
		entry := v.(*CachedFlowPath)
		if (srcIA == 0 || entry.SrcIA == srcIA) && (dstIA == 0 || entry.DstIA == dstIA) {
			c.flows.Delete(k)
			count++
		}
		return true
	})
	return count
}

// InvalidateByFingerprint removes all flows utilizing the given SCION path fingerprint.
func (c *FlowPathCache) InvalidateByFingerprint(fingerprint string) int {
	if fingerprint == "" {
		return 0
	}
	count := 0
	c.flows.Range(func(k, v any) bool {
		entry := v.(*CachedFlowPath)
		if entry.Fingerprint == fingerprint {
			c.flows.Delete(k)
			count++
		}
		return true
	})
	return count
}

// Len returns the current count of cached flows.
func (c *FlowPathCache) Len() int {
	count := 0
	c.flows.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

// Clear flushes all entries from the cache.
func (c *FlowPathCache) Clear() {
	c.flows.Range(func(k, _ any) bool {
		c.flows.Delete(k)
		return true
	})
}

// Cleanup iterates through the cache and evicts expired and idle flows.
func (c *FlowPathCache) Cleanup() int {
	now := time.Now()
	ttlNano := c.flowTTL.Nanoseconds()
	evicted := 0

	c.flows.Range(func(k, v any) bool {
		entry := v.(*CachedFlowPath)
		lastSeen := atomic.LoadInt64(&entry.lastSeen)

		// Check idle timeout
		if now.UnixNano()-lastSeen > ttlNano {
			c.flows.Delete(k)
			evicted++
			return true
		}

		// Check hard expiry
		if !entry.Expiry.IsZero() && now.After(entry.Expiry) {
			c.flows.Delete(k)
			evicted++
			return true
		}

		return true
	})

	return evicted
}

func (c *FlowPathCache) cleanupLoop() {
	ticker := time.NewTicker(DefaultCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.Cleanup()
		}
	}
}

// Close stops the background cleanup goroutine.
func (c *FlowPathCache) Close() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
}
