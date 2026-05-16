package device

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/scionproto/scion/pkg/addr"
)

type ScionDeviceConfig struct {
	Enabled   bool
	ConfigDir string
}

type scionTopologyFile struct {
	ISDAS        string                       `json:"isd_as"`
	BorderRouter map[string]scionBorderRouter `json:"border_routers"`
}

type scionBorderRouter struct {
	InternalAddr string `json:"internal_addr"`
}

func ScionDeviceConfigFromEnv() ScionDeviceConfig {
	configDir := os.Getenv("SCION_CONFIG_DIR")

	enabled := os.Getenv("SCION_ENABLED") == "true" || configDir != ""

	return ScionDeviceConfig{
		Enabled:   enabled,
		ConfigDir: configDir,
	}
}

func loadSCIONTopology(configDir string) (*scionTopologyFile, error) {
	if configDir == "" {
		return nil, fmt.Errorf("empty SCION config dir")
	}

	topoPath := filepath.Join(configDir, "topology.json")

	raw, err := os.ReadFile(topoPath)
	if err != nil {
		return nil, fmt.Errorf("read topology.json: %w", err)
	}

	var topo scionTopologyFile
	if err := json.Unmarshal(raw, &topo); err != nil {
		return nil, fmt.Errorf("parse topology.json: %w", err)
	}

	if topo.ISDAS == "" {
		return nil, fmt.Errorf("topology.json missing isd_as")
	}

	return &topo, nil
}

func loadLocalIAFromTopology(configDir string) (addr.IA, error) {
	topo, err := loadSCIONTopology(configDir)
	if err != nil {
		return 0, err
	}

	localIA, err := addr.ParseIA(topo.ISDAS)
	if err != nil {
		return 0, fmt.Errorf("parse local IA %q: %w", topo.ISDAS, err)
	}

	return localIA, nil
}

func loadBRAddrFromTopology(configDir string) (*net.UDPAddr, error) {
	topo, err := loadSCIONTopology(configDir)
	if err != nil {
		return nil, err
	}

	for name, br := range topo.BorderRouter {
		if br.InternalAddr == "" {
			continue
		}

		addr, err := net.ResolveUDPAddr("udp", br.InternalAddr)
		if err != nil {
			return nil, fmt.Errorf("parse border router %s internal_addr %q: %w", name, br.InternalAddr, err)
		}

		return addr, nil
	}

	return nil, fmt.Errorf("topology.json has no border router internal_addr")
}
