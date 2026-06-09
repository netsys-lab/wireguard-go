package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
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

func logDialCheck(network, address string) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.Dial(network, address)
	if err != nil {
		log.Printf("[PATHSRV-DIAL] %s %s FAILED: %v", network, address, err)
		return
	}
	_ = conn.Close()
	log.Printf("[PATHSRV-DIAL] %s %s OK", network, address)
}

func logDialChecksFromTopology(topoPath string) {
	raw, err := os.ReadFile(topoPath)
	if err != nil {
		log.Printf("[PATHSRV-DIAL] read topology failed: %v", err)
		return
	}

	var topo map[string]any
	if err := json.Unmarshal(raw, &topo); err != nil {
		log.Printf("[PATHSRV-DIAL] parse topology failed: %v", err)
		return
	}

	checkServiceMap := func(section string) {
		services, ok := topo[section].(map[string]any)
		if !ok {
			return
		}

		for name, v := range services {
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}

			addr, _ := m["addr"].(string)
			if addr == "" {
				continue
			}

			log.Printf("[PATHSRV-DIAL] %s %s addr=%s", section, name, addr)
			logDialCheck("tcp", addr)
		}
	}

	checkServiceMap("control_service")
	checkServiceMap("discovery_service")

	brs, ok := topo["border_routers"].(map[string]any)
	if !ok {
		return
	}

	for brName, brVal := range brs {
		br, ok := brVal.(map[string]any)
		if !ok {
			continue
		}

		if internal, _ := br["internal_addr"].(string); internal != "" {
			log.Printf("[PATHSRV-DIAL] border_router %s internal_addr=%s", brName, internal)
			logDialCheck("udp", internal)
		}

		ifaces, ok := br["interfaces"].(map[string]any)
		if !ok {
			continue
		}

		for ifid, ifVal := range ifaces {
			iface, ok := ifVal.(map[string]any)
			if !ok {
				continue
			}

			underlay, ok := iface["underlay"].(map[string]any)
			if !ok {
				continue
			}

			if local, _ := underlay["local"].(string); local != "" {
				log.Printf("[PATHSRV-DIAL] br=%s ifid=%s underlay.local=%s", brName, ifid, local)
				logDialCheck("udp", local)
			}

			if remote, _ := underlay["remote"].(string); remote != "" {
				log.Printf("[PATHSRV-DIAL] br=%s ifid=%s underlay.remote=%s", brName, ifid, remote)
				logDialCheck("udp", remote)
			}
		}
	}
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

	ia := asInfo.IA()
	mtu := asInfo.MTU()

	log.Printf("[PATHSRV] AS info: IA=%s", ia)
	log.Printf("[PATHSRV] ASInfo MTU=%d", mtu)

	log.Printf("[PATHSRV-CONFIG] topology=%s", topoPath)
	log.Printf("[PATHSRV-CONFIG] certsDir=%s", certsDir)

	rawTopo, err := os.ReadFile(topoPath)
	if err != nil {
		log.Printf("[PATHSRV-CONFIG] failed to read topology raw: %v", err)
	} else {
		log.Printf("[PATHSRV-CONFIG] raw topology.json:\n%s", string(rawTopo))
	}
	logDialChecksFromTopology(topoPath)

	log.Printf("[PATHSRV-CONFIG] asInfo=%+v", asInfo)

	// Create context with timeout for initial connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Printf("[PATHSRV-CONNECT] creating standalone connector")

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
	log.Printf("[PATHSRV-QUERY] RetrievePaths called")
	log.Printf("[PATHSRV-QUERY] requested src=%s dst=%s", src, dst)

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

	log.Printf("[PATHSRV] Querying connector.Paths(dst=%s, src=%s)", dst, src)
	// Fetch paths directly from the internal engine
	paths, err := r.connector.Paths(ctx, dst, src, types.PathReqFlags{})
	if err != nil {
		log.Printf("[PATHSRV] ERROR: connector.Paths failed: %v", err)
		return nil, fmt.Errorf("embedded engine failed to fetch paths: %w", err)
	}

	log.Printf("[PATHSRV] Got %d paths from connector", len(paths))

	for i, p := range paths {
		meta := p.Metadata()
		log.Printf("[PATHSRV] Path %d nextHop=%v meta=%+v", i, p.UnderlayNextHop(), meta)
	}

	// Log path details for debugging
	for i := range paths {
		log.Printf("[PATHSRV] Path %d: available", i)
	}

	return paths, nil
}
