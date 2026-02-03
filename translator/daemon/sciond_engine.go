package daemon

import (
	"context"
	"fmt"
	"path/filepath"

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
	topoPath := filepath.Join(configDir, "topology.json")
	certsDir := filepath.Join(configDir, "certs")

	asInfo, err := daemon.LoadASInfoFromFile(topoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load topology from %s: %w", topoPath, err)
	}

	conn, err := daemon.NewStandaloneConnector(
		context.Background(),
		asInfo,
		daemon.WithCertsDir(certsDir),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize standalone SCION connector: %w", err)
	}

	return &SciondRetriever{
		connector: conn,
	}, nil
}

func (r *SciondRetriever) RetrievePaths(ctx context.Context, src, dst addr.IA) ([]snet.Path, error) {
	// Fetch paths directly from the internal engine
	paths, err := r.connector.Paths(ctx, dst, src, types.PathReqFlags{})
	if err != nil {
		return nil, fmt.Errorf("embedded engine failed to fetch paths: %w", err)
	}

	return paths, nil
}
