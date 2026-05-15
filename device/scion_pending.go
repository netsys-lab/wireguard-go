package device

import (
	"log"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

type pendingSCIONKey struct {
	src addr.IA
	dst addr.IA
}

type pendingSCIONPacket struct {
	packet   []byte
	isIPv6   bool
	hostPort int
	created  time.Time
}

type PendingSCIONQueue struct {
	mu        sync.Mutex
	packets   map[pendingSCIONKey][]pendingSCIONPacket
	maxPerKey int
	maxAge    time.Duration
}

func NewPendingSCIONQueue(maxPerKey int, maxAge time.Duration) *PendingSCIONQueue {
	log.Printf("[SCION-PENDING] queue created maxPerKey=%d maxAge=%s", maxPerKey, maxAge)

	return &PendingSCIONQueue{
		packets:   make(map[pendingSCIONKey][]pendingSCIONPacket),
		maxPerKey: maxPerKey,
		maxAge:    maxAge,
	}
}

func (q *PendingSCIONQueue) Enqueue(src, dst addr.IA, pkt []byte, isIPv6 bool, hostPort int) {
	q.mu.Lock()
	defer q.mu.Unlock()

	k := pendingSCIONKey{src: src, dst: dst}
	now := time.Now()

	list := q.packets[k]

	filtered := list[:0]
	droppedExpired := 0
	for _, p := range list {
		if now.Sub(p.created) <= q.maxAge {
			filtered = append(filtered, p)
		} else {
			droppedExpired++
		}
	}
	list = filtered

	droppedOldest := false
	if len(list) >= q.maxPerKey {
		list = list[1:]
		droppedOldest = true
	}

	pktCopy := append([]byte(nil), pkt...)
	list = append(list, pendingSCIONPacket{
		packet:   pktCopy,
		isIPv6:   isIPv6,
		hostPort: hostPort,
		created:  now,
	})

	q.packets[k] = list

	log.Printf("[SCION-PENDING] enqueue: src=%s dst=%s len=%d queued=%d droppedExpired=%d droppedOldest=%v",
		src, dst, len(pktCopy), len(list), droppedExpired, droppedOldest)
}

func (q *PendingSCIONQueue) Pop(src, dst addr.IA) []pendingSCIONPacket {
	q.mu.Lock()
	defer q.mu.Unlock()

	k := pendingSCIONKey{src: src, dst: dst}
	list := q.packets[k]
	delete(q.packets, k)

	now := time.Now()
	valid := make([]pendingSCIONPacket, 0, len(list))
	droppedExpired := 0

	for _, p := range list {
		if now.Sub(p.created) <= q.maxAge {
			valid = append(valid, p)
		} else {
			droppedExpired++
		}
	}

	log.Printf("[SCION-PENDING] pop: src=%s dst=%s returned=%d droppedExpired=%d",
		src, dst, len(valid), droppedExpired)

	return valid
}
