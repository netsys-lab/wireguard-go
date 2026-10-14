package device

import (
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

/*
Implements the pending SCION packet queue.

When a SCION-mapped packet arrives but no path is currently cached,
the packet is copied into this queue instead of blocking the TUN reader or dropping the packet immediately.

Packets are grouped by source/destination IA pair and are retried once the asynchronous path refresh completes.
*/

type pendingSCIONKey struct {
	src addr.IA
	dst addr.IA
}

type pendingSCIONPacket struct {
	packet   []byte
	isIPv6   bool
	hostPort int
	created  time.Time
	packetID uint64 // SCION packet correlation ID
}

type PendingSCIONQueue struct {
	mu        sync.Mutex
	packets   map[pendingSCIONKey][]pendingSCIONPacket
	maxPerKey int
	maxAge    time.Duration
}

func NewPendingSCIONQueue(maxPerKey int, maxAge time.Duration) *PendingSCIONQueue {
	return &PendingSCIONQueue{
		packets:   make(map[pendingSCIONKey][]pendingSCIONPacket),
		maxPerKey: maxPerKey,
		maxAge:    maxAge,
	}
}

func (q *PendingSCIONQueue) Enqueue(src, dst addr.IA, pkt []byte, isIPv6 bool, hostPort int, packetID uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	k := pendingSCIONKey{src: src, dst: dst}
	now := time.Now()

	list := q.packets[k]

	filtered := list[:0]
	for _, p := range list {
		if now.Sub(p.created) <= q.maxAge {
			filtered = append(filtered, p)
		}
	}
	list = filtered

	if len(list) >= q.maxPerKey {
		list = list[1:]
	}

	pktCopy := append([]byte(nil), pkt...)
	list = append(list, pendingSCIONPacket{
		packet:   pktCopy,
		isIPv6:   isIPv6,
		hostPort: hostPort,
		created:  now,
		packetID: packetID,
	})

	q.packets[k] = list
}

func (q *PendingSCIONQueue) Pop(src, dst addr.IA) []pendingSCIONPacket {
	q.mu.Lock()
	defer q.mu.Unlock()

	k := pendingSCIONKey{src: src, dst: dst}
	list := q.packets[k]
	delete(q.packets, k)

	now := time.Now()
	valid := make([]pendingSCIONPacket, 0, len(list))

	for _, p := range list {
		if now.Sub(p.created) <= q.maxAge {
			valid = append(valid, p)
		}
	}

	return valid
}
