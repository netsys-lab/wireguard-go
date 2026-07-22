package device

import (
	"encoding/json"
	"fmt"
)

type SCIONInfo struct {
	LocalIA   string `json:"localIA"`
	LocalIPv4 string `json:"localIPv4,omitempty"`
	LocalIPv6 string `json:"localIPv6,omitempty"`
	BRAddr    string `json:"brAddr,omitempty"`
	PortRange string `json:"portRange,omitempty"`
}

func (device *Device) SCIONInfoJSON() (string, error) {
	if device == nil || device.translator == nil {
		return "{}", nil
	}

	info := SCIONInfo{
		LocalIA: device.translator.LocalIA().String(),
	}

	ipv4, err := device.translator.WGSrcIPv4()
	if err == nil && ipv4 != nil {
		info.LocalIPv4 = ipv4.String()
	}

	ipv6, err := device.translator.WGSrcIPv6()
	if err == nil && ipv6 != nil {
		info.LocalIPv6 = ipv6.String()
	}

	if br := device.translator.BRAddr(); br != nil {
		info.BRAddr = br.String()
	}

	if dp := device.translator.DispatchedPorts(); dp.Valid {
		info.PortRange = fmt.Sprintf("%d-%d", dp.Start, dp.End)
	}

	raw, err := json.Marshal(info)
	if err != nil {
		return "", err
	}

	return string(raw), nil
}

func (device *Device) MustSCIONInfoJSON() string {
	out, err := device.SCIONInfoJSON()
	if err != nil {
		if device != nil && device.log != nil {
			device.log.Errorf("[SCION-INFO] failed to marshal SCION info: %v", err)
		}
		return "{}"
	}
	return out
}
