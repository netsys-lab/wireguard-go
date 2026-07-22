package device

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/scionproto/scion/pkg/addr"
	"golang.zx2c4.com/wireguard/scionlog"
	"golang.zx2c4.com/wireguard/translator/header_parsing"
)

type ScionDeviceConfig struct {
	Enabled       bool
	ConfigDir     string
	InterfaceName string
	LocalIPv4     netip.Addr
	LocalIPv6     netip.Addr
	LogConfig     *scionlog.LogConfig
	PolicyFile    string
}

type scionTopologyFile struct {
	ISDAS           string                       `json:"isd_as"`
	DispatchedPorts string                       `json:"dispatched_ports"`
	BorderRouter    map[string]scionBorderRouter `json:"border_routers"`
}

type scionBorderRouter struct {
	InternalAddr string `json:"internal_addr"`
}

func parseDispatchedPorts(s string) (header_parsing.DispatchPortRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return header_parsing.DispatchPortRange{}, nil
	}

	parts := strings.Split(s, "-")

	parsePort := func(v string) (uint16, error) {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, err
		}
		if n < 1 || n > 65535 {
			return 0, fmt.Errorf("port out of range: %d", n)
		}
		return uint16(n), nil
	}

	if len(parts) == 1 {
		p, err := parsePort(parts[0])
		if err != nil {
			return header_parsing.DispatchPortRange{}, err
		}
		return header_parsing.DispatchPortRange{
			Start: p,
			End:   p,
			Valid: true,
		}, nil
	}

	if len(parts) == 2 {
		start, err := parsePort(parts[0])
		if err != nil {
			return header_parsing.DispatchPortRange{}, err
		}

		end, err := parsePort(parts[1])
		if err != nil {
			return header_parsing.DispatchPortRange{}, err
		}

		if start > end {
			return header_parsing.DispatchPortRange{}, fmt.Errorf("invalid dispatched_ports range: %q", s)
		}

		return header_parsing.DispatchPortRange{
			Start: start,
			End:   end,
			Valid: true,
		}, nil
	}

	return header_parsing.DispatchPortRange{}, fmt.Errorf("invalid dispatched_ports: %q", s)
}

func ScionDeviceConfigFromEnv() ScionDeviceConfig {
	configDir := os.Getenv("SCION_CONFIG_DIR")

	enabled := os.Getenv("SCION_ENABLED") == "true" || configDir != ""

	logCfg := scionlog.ConfigFromEnv()
	policyFile := os.Getenv("SCION_POLICY_FILE")

	return ScionDeviceConfig{
		Enabled:    enabled,
		ConfigDir:  configDir,
		LogConfig:  &logCfg,
		PolicyFile: policyFile,
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

func loadDispatchedPortsFromTopology(configDir string) (header_parsing.DispatchPortRange, error) {
	topo, err := loadSCIONTopology(configDir)
	if err != nil {
		return header_parsing.DispatchPortRange{}, err
	}

	dispatchedPorts, err := parseDispatchedPorts(topo.DispatchedPorts)
	if err != nil {
		return header_parsing.DispatchPortRange{}, fmt.Errorf("parse dispatched_ports %q: %w", topo.DispatchedPorts, err)
	}

	return dispatchedPorts, nil
}
