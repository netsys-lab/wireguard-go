package daemon

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/snet"
)

type SciondRetriever struct {
	connector daemon.Connector
}

// configDir: The directory containing 'topology.json' and a 'certs' subdirectory.
func NewSciondRetriever(configDir string) (*SciondRetriever, error) {
	log.Printf("[PATHSRV] NewSciondRetriever: configDir=%s", configDir)

	topoPath := filepath.Join(configDir, "topology.json")
	certsDir := filepath.Join(configDir, "certs")

	asInfo, err := daemon.LoadASInfoFromFile(topoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load topology from %s: %w", topoPath, err)
	}
	log.Printf("[PATHSRV] Loaded AS info: IA=%s", asInfo.IA)

	// Create context with timeout for initial connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := daemon.NewStandaloneConnector(
		ctx,
		asInfo,
		daemon.WithCertsDir(certsDir),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize standalone SCION connector: %w", err)
	}

	log.Printf("[PATHSRV] Created standalone connector successfully")

	// Test connectivity - try to get local IA
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	localIA, err := conn.LocalIA(ctx2)
	if err != nil {
		log.Printf("[PATHSRV] WARNING: Could not get local IA: %v", err)
	} else {
		log.Printf("[PATHSRV] Local IA: %s", localIA)
	}

	// Get interfaces
	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel3()
	ifaces, err := conn.Interfaces(ctx3)
	if err != nil {
		log.Printf("[PATHSRV] WARNING: Could not get interfaces: %v", err)
	} else {
		log.Printf("[PATHSRV] Interfaces: %v", ifaces)
	}

	return &SciondRetriever{
		connector: conn,
	}, nil
}

func (r *SciondRetriever) RetrievePaths(ctx context.Context, src, dst addr.IA) ([]snet.Path, error) {
	log.Printf("[PATHSRV] RetrievePaths: src=%s, dst=%s", src, dst)

	// Test: Get local IA first
	localIA, err := r.connector.LocalIA(ctx)
	if err != nil {
		log.Printf("[PATHSRV] ERROR: Cannot get local IA: %v", err)
	} else {
		log.Printf("[PATHSRV] Local IA is: %s", localIA)
	}

	// Test: Get interfaces
	ifaces, err := r.connector.Interfaces(ctx)
	if err != nil {
		log.Printf("[PATHSRV] ERROR: Cannot get interfaces: %v", err)
	} else {
		log.Printf("[PATHSRV] Got %d interfaces: %v", len(ifaces), ifaces)
	}

	// Fetch paths directly from the internal engine
	paths, err := r.connector.Paths(ctx, dst, src, types.PathReqFlags{})
	if err != nil {
		log.Printf("[PATHSRV] ERROR: connector.Paths failed: %v", err)
		return nil, fmt.Errorf("embedded engine failed to fetch paths: %w", err)
	}

	log.Printf("[PATHSRV] Got %d paths from connector", len(paths))

	// Log path details for debugging
	for i := range paths {
		log.Printf("[PATHSRV] Path %d: available", i)
	}

	return paths, nil
}
