package pathpolicy

import (
	"fmt"
	"log"
	"os"

	pathpool "golang.zx2c4.com/wireguard/translator/pathpool"
)

// Engine is the top-level path policy engine. It holds a parsed and resolved
// policy file and provides the SelectPaths entry point for the translator.
type Engine struct {
	file     *PolicyFile
	resolved map[string]*ResolvedPolicy
}

// NewEngine creates a policy engine from a parsed PolicyFile.
// It resolves all policy inheritance chains at construction time.
func NewEngine(pf *PolicyFile) (*Engine, error) {
	resolved, err := pf.ResolvePolicies()
	if err != nil {
		return nil, fmt.Errorf("resolve policies: %w", err)
	}

	return &Engine{
		file:     pf,
		resolved: resolved,
	}, nil
}

// LoadEngine loads a policy file from disk and creates an Engine.
func LoadEngine(path string) (*Engine, error) {
	pf, err := LoadPolicyFile(path)
	if err != nil {
		return nil, err
	}
	return NewEngine(pf)
}

// LoadEngineFromPaths tries to load a policy engine from the given paths
// in order. Returns the first successfully loaded engine.
// Returns nil (no engine, no error) if no policy file exists at any path.
func LoadEngineFromPaths(paths ...string) (*Engine, error) {
	for _, p := range paths {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue
		}

		engine, err := LoadEngine(p)
		if err != nil {
			return nil, fmt.Errorf("load policy from %s: %w", p, err)
		}

		log.Printf("[PATHPOLICY] loaded policy from %s (%d matchers, %d policies)",
			p, len(engine.file.Matchers), len(engine.file.Policies))
		return engine, nil
	}

	return nil, nil
}

// Matchers returns the list of matchers from the loaded policy file.
// Used by the device layer for policy-aware path display.
func (e *Engine) Matchers() []Matcher {
	if e == nil || e.file == nil {
		return nil
	}
	return e.file.Matchers
}

// SelectPaths applies the full policy pipeline to a set of cached paths:
//  1. Match the packet info to a policy name
//  2. Filter paths using the resolved policy (ACL, sequence, requirements)
//  3. Sort the remaining paths according to the ordering rules
//  4. If no paths survive, try the failover policy chain
//
// Returns the filtered and sorted paths. If the engine is nil or no policy
// applies, the original paths are returned unchanged.
func (e *Engine) SelectPaths(info PacketInfo, paths []pathpool.CachedPath) []pathpool.CachedPath {
	if e == nil || len(paths) == 0 {
		return paths
	}

	// Step 1: Match packet to policy.
	policyName := MatchPacket(e.file.Matchers, info)

	log.Printf("[PATHPOLICY] packet matched policy=%q (src=%s dst=%s proto=%s dscp=%d)",
		policyName, info.SrcIA, info.DstIA, info.Protocol, info.DSCP)

	// Step 2-4: Apply policy with failover chain.
	return e.applyPolicyChain(policyName, paths)
}

// applyPolicyChain applies the named policy and follows the failover chain
// if the result is empty. Guards against infinite loops.
func (e *Engine) applyPolicyChain(policyName string, paths []pathpool.CachedPath) []pathpool.CachedPath {
	visited := map[string]bool{}
	currentPolicy := policyName

	for {
		if visited[currentPolicy] {
			log.Printf("[PATHPOLICY] failover loop detected at policy=%q, returning all paths", currentPolicy)
			return paths
		}
		visited[currentPolicy] = true

		rp, ok := e.resolved[currentPolicy]
		if !ok {
			log.Printf("[PATHPOLICY] policy %q not found, returning all paths", currentPolicy)
			return paths
		}

		// Apply filters.
		filtered := FilterPaths(rp, paths)

		log.Printf("[PATHPOLICY] policy=%q filtered: %d -> %d paths",
			currentPolicy, len(paths), len(filtered))

		if len(filtered) > 0 {
			// Apply ordering.
			sorted := SortPaths(rp.Ordering, filtered)
			return sorted
		}

		// No paths survived. Try failover.
		if rp.Failover == "" {
			log.Printf("[PATHPOLICY] policy=%q yielded 0 paths, no failover", currentPolicy)
			return filtered // empty
		}

		log.Printf("[PATHPOLICY] policy=%q yielded 0 paths, failover to %q",
			currentPolicy, rp.Failover)
		currentPolicy = rp.Failover
	}
}
