package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/daemon/types"
	"github.com/scionproto/scion/pkg/snet"
	"golang.zx2c4.com/wireguard/scionlog"
	"golang.zx2c4.com/wireguard/translator/pathpool"
)

type SciondRetriever struct {
	connector daemon.Connector
	log       *scionlog.Logger
}

func (r *SciondRetriever) logDialCheck(network, address string) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.Dial(network, address)
	if err != nil {
		r.log.Infof(scionlog.ComponentPath, "[PATHSRV-DIAL] %s %s FAILED: %v", network, address, err)
		return
	}
	_ = conn.Close()
	r.log.Infof(scionlog.ComponentPath, "[PATHSRV-DIAL] %s %s OK", network, address)
}

func (r *SciondRetriever) logDialChecksFromTopology(topoPath string) {
	raw, err := os.ReadFile(topoPath)
	if err != nil {
		r.log.Infof(scionlog.ComponentPath, "[PATHSRV-DIAL] read topology failed: %v", err)
		return
	}

	var topo map[string]any
	if err := json.Unmarshal(raw, &topo); err != nil {
		r.log.Infof(scionlog.ComponentPath, "[PATHSRV-DIAL] parse topology failed: %v", err)
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

			r.log.Infof(scionlog.ComponentPath, "[PATHSRV-DIAL] %s %s addr=%s", section, name, addr)
			r.logDialCheck("tcp", addr)
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
			r.log.Infof(scionlog.ComponentPath, "[PATHSRV-DIAL] border_router %s internal_addr=%s", brName, internal)
			r.logDialCheck("udp", internal)
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
				r.log.Infof(scionlog.ComponentPath, "[PATHSRV-DIAL] br=%s ifid=%s underlay.local=%s", brName, ifid, local)
				r.logDialCheck("udp", local)
			}

			if remote, _ := underlay["remote"].(string); remote != "" {
				r.log.Infof(scionlog.ComponentPath, "[PATHSRV-DIAL] br=%s ifid=%s underlay.remote=%s", brName, ifid, remote)
				r.logDialCheck("udp", remote)
			}
		}
	}
}

// configDir: The directory containing 'topology.json' and a 'certs' subdirectory.
func NewSciondRetriever(configDir string, log *scionlog.Logger) (*SciondRetriever, error) {
	if log == nil {
		log = scionlog.NewLogger(
			func(string, ...any) {},
			func(string, ...any) {},
		)
	}

	r := &SciondRetriever{log: log}
	r.log.Infof(scionlog.ComponentPath, "[PATHSRV] NewSciondRetriever: configDir=%s", configDir)

	topoPath := filepath.Join(configDir, "topology.json")
	certsDir := filepath.Join(configDir, "certs")

	asInfo, err := daemon.LoadASInfoFromFile(topoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load topology from %s: %w", topoPath, err)
	}

	ia := asInfo.IA()
	mtu := asInfo.MTU()

	r.log.Infof(scionlog.ComponentPath, "[PATHSRV] AS info: IA=%s", ia)
	r.log.Infof(scionlog.ComponentPath, "[PATHSRV] ASInfo MTU=%d", mtu)

	r.log.Infof(scionlog.ComponentInit, "[PATHSRV-CONFIG] topology=%s", topoPath)
	r.log.Infof(scionlog.ComponentInit, "[PATHSRV-CONFIG] certsDir=%s", certsDir)

	rawTopo, err := os.ReadFile(topoPath)
	if err != nil {
		r.log.Infof(scionlog.ComponentInit, "[PATHSRV-CONFIG] failed to read topology raw: %v", err)
	} else {
		r.log.Infof(scionlog.ComponentInit, "[PATHSRV-CONFIG] raw topology.json:\n%s", string(rawTopo))
	}
	r.logDialChecksFromTopology(topoPath)

	r.log.Infof(scionlog.ComponentInit, "[PATHSRV-CONFIG] asInfo=%+v", asInfo)

	// Create context with timeout for initial connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r.log.Infof(scionlog.ComponentInit, "[PATHSRV-CONNECT] creating standalone connector")

	conn, err := daemon.NewStandaloneConnector(
		ctx,
		asInfo,
		daemon.WithCertsDir(certsDir),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize standalone SCION connector: %w", err)
	}

	r.log.Infof(scionlog.ComponentPath, "[PATHSRV] Created standalone connector successfully")

	// Test connectivity - try to get local IA
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	localIA, err := conn.LocalIA(ctx2)
	if err != nil {
		r.log.Infof(scionlog.ComponentPath, "[PATHSRV] WARNING: Could not get local IA: %v", err)
	} else {
		r.log.Infof(scionlog.ComponentPath, "[PATHSRV] Local IA: %s", localIA)
	}

	// Get interfaces
	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel3()
	ifaces, err := conn.Interfaces(ctx3)
	if err != nil {
		r.log.Infof(scionlog.ComponentPath, "[PATHSRV] WARNING: Could not get interfaces: %v", err)
	} else {
		r.log.Infof(scionlog.ComponentPath, "[PATHSRV] Interfaces: %v", ifaces)
	}

	r.connector = conn
	return r, nil
}

func (r *SciondRetriever) RetrievePaths(ctx context.Context, src, dst addr.IA) ([]snet.Path, error) {
	refreshID, hasRefreshID := pathpool.RefreshIDFromContext(ctx)
	rid := ""
	if hasRefreshID {
		rid = fmt.Sprintf("refreshId=%d ", refreshID)
	}

	r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %sphase=RetrievePaths event=start src=%s dst=%s", rid, src, dst)
	retrieveStart := time.Now()

	// Phase: LocalIA probe
	r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %sphase=local-ia event=start", rid)
	localIAStart := time.Now()
	localIA, err := r.connector.LocalIA(ctx)
	localIAElapsed := time.Since(localIAStart)
	if err != nil {
		r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %sphase=local-ia event=complete elapsedMs=%d err=%v", rid, localIAElapsed.Milliseconds(), err)
	} else {
		r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %sphase=local-ia event=complete elapsedMs=%d localIA=%s", rid, localIAElapsed.Milliseconds(), localIA)
	}

	// Phase: Interfaces probe
	r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %sphase=interfaces event=start", rid)
	ifacesStart := time.Now()
	ifaces, err := r.connector.Interfaces(ctx)
	ifacesElapsed := time.Since(ifacesStart)
	if err != nil {
		r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %sphase=interfaces event=complete elapsedMs=%d err=%v", rid, ifacesElapsed.Milliseconds(), err)
	} else {
		r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %sphase=interfaces event=complete elapsedMs=%d count=%d", rid, ifacesElapsed.Milliseconds(), len(ifaces))
	}

	// Phase: connector.Paths
	r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %sphase=connector.Paths event=start dst=%s src=%s", rid, dst, src)
	pathsStart := time.Now()
	paths, err := r.connector.Paths(ctx, dst, src, types.PathReqFlags{})
	pathsElapsed := time.Since(pathsStart)
	if err != nil {
		r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %sphase=connector.Paths event=complete elapsedMs=%d err=%v", rid, pathsElapsed.Milliseconds(), err)
		return nil, fmt.Errorf("embedded engine failed to fetch paths: %w", err)
	}
	r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %sphase=connector.Paths event=complete elapsedMs=%d pathCount=%d", rid, pathsElapsed.Milliseconds(), len(paths))

	// Phase: result processing
	r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %sphase=result-processing event=start pathCount=%d", rid, len(paths))
	processingStart := time.Now()
	for i, p := range paths {
		meta := p.Metadata()
		r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %spath[%d] nextHop=%v expiry=%v", rid, i, p.UnderlayNextHop(), meta.Expiry)
	}
	processingElapsed := time.Since(processingStart)
	r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %sphase=result-processing event=complete elapsedMs=%d", rid, processingElapsed.Milliseconds())

	totalElapsed := time.Since(retrieveStart)
	r.log.Infof(scionlog.ComponentPath, "[SCION-PATH-TRACE] %sphase=RetrievePaths event=complete elapsedMs=%d pathCount=%d", rid, totalElapsed.Milliseconds(), len(paths))

	return paths, nil
}
