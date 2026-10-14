package pathpool

import (
	"fmt"
	"net"
	"time"

	"github.com/scionproto/scion/pkg/addr"
)

/*
Provides a read-only, JSON-safe snapshot view of the SCION PathPool.

Converts the internal cached SCION paths into simple DTO structs, containing:
 IA pairs,
 available paths,
 selected path information,
 next hop,
 expiry,
 MTU,
 interfaces/hops,
 refresh state,
 and last errors.
*/

const DefaultSelectionStrategy = "first-valid"

type PathSnapshot struct {
	Strategy string         `json:"strategy"`
	Pairs    []PathPairInfo `json:"pairs"`
}

type PathPairInfo struct {
	SrcIA               string     `json:"srcIA"`
	DstIA               string     `json:"dstIA"`
	AvailablePaths      int        `json:"availablePaths"`
	SelectedFingerprint string     `json:"selectedFingerprint"`
	LastRefresh         string     `json:"lastRefresh"`
	LastError           string     `json:"lastError,omitempty"`
	InFlight            bool       `json:"inFlight"`
	Paths               []PathInfo `json:"paths"`
}

type PathInfo struct {
	Index       int      `json:"index"`
	Selected    bool     `json:"selected"`
	Fingerprint string   `json:"fingerprint"`
	NextHop     string   `json:"nextHop"`
	Expiry      string   `json:"expiry"`
	MTU         uint16   `json:"mtu"`
	Interfaces  []string `json:"interfaces"`
}

func (pp *PathPool) Snapshot() PathSnapshot {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	snapshot := PathSnapshot{
		Strategy: DefaultSelectionStrategy,
		Pairs:    make([]PathPairInfo, 0, len(pp.cache)),
	}

	for k, entry := range pp.cache {
		valid := filterValid(entry.paths)

		pair := PathPairInfo{
			SrcIA:          k.src.String(),
			DstIA:          k.dst.String(),
			AvailablePaths: len(valid),
			LastRefresh:    formatTime(entry.lastRefresh),
			InFlight:       pp.inflight[k] != nil,
			Paths:          make([]PathInfo, 0, len(valid)),
		}

		if entry.lastError != nil {
			pair.LastError = entry.lastError.Error()
		}

		selectedIndex := selectSnapshotPathIndex(valid)
		if selectedIndex >= 0 && selectedIndex < len(valid) {
			pair.SelectedFingerprint = valid[selectedIndex].Fingerprint
		}

		for i, p := range valid {
			info := pathInfoFromCachedPath(i, p)
			info.Selected = i == selectedIndex
			pair.Paths = append(pair.Paths, info)
		}

		snapshot.Pairs = append(snapshot.Pairs, pair)
	}

	return snapshot
}

func selectSnapshotPathIndex(paths []CachedPath) int {
	if len(paths) == 0 {
		return -1
	}

	// Must match current runtime selection strategy.
	// Current strategy in translate.go is: paths[0]
	return 0
}

func pathInfoFromCachedPath(index int, p CachedPath) PathInfo {
	info := PathInfo{
		Index:       index,
		Fingerprint: p.Fingerprint,
		NextHop:     formatUDPAddr(p.NextHop),
		Expiry:      formatTime(p.Expiry),
	}

	meta := p.Path.Metadata()
	if meta != nil {
		info.MTU = meta.MTU

		for _, iface := range meta.Interfaces {
			info.Interfaces = append(info.Interfaces, fmt.Sprint(iface))
		}
	}

	return info
}

func formatUDPAddr(a *net.UDPAddr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339Nano)
}

// Optional helper for targeted lookup from UI later.
func (pp *PathPool) SnapshotFor(src, dst addr.IA) PathPairInfo {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	k := key{src: src, dst: dst}
	entry := pp.cache[k]

	pair := PathPairInfo{
		SrcIA: src.String(),
		DstIA: dst.String(),
	}

	if entry == nil {
		return pair
	}

	valid := filterValid(entry.paths)

	pair.AvailablePaths = len(valid)
	pair.LastRefresh = formatTime(entry.lastRefresh)
	pair.InFlight = pp.inflight[k] != nil

	if entry.lastError != nil {
		pair.LastError = entry.lastError.Error()
	}

	selectedIndex := selectSnapshotPathIndex(valid)
	if selectedIndex >= 0 && selectedIndex < len(valid) {
		pair.SelectedFingerprint = valid[selectedIndex].Fingerprint
	}

	for i, p := range valid {
		info := pathInfoFromCachedPath(i, p)
		info.Selected = i == selectedIndex
		pair.Paths = append(pair.Paths, info)
	}

	return pair
}
