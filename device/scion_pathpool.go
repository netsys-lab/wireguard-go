package device

import (
	"encoding/json"
)

/*
SCIONPathSnapshotJSON bridges Device → pathpool.Snapshot() as JSON.

This is the snapshot bridge to the SCION PathPool, consumed by the
frontend for path selection display and the future Paths-per-Flow UI.
*/

func (device *Device) SCIONPathSnapshotJSON() (string, error) {
	if device == nil || device.pathPool == nil {
		return `{"strategy":"","pairs":[]}`, nil
	}

	snapshot := device.pathPool.Snapshot()

	raw, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}

	return string(raw), nil
}

func (device *Device) MustSCIONPathSnapshotJSON() string {
	out, err := device.SCIONPathSnapshotJSON()
	if err != nil {
		if device != nil && device.log != nil {
			device.log.Errorf("[SCION-PATHPOOL] failed to marshal path snapshot: %v", err)
		}
		return `{"strategy":"","pairs":[]}`
	}
	return out
}
