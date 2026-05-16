package device

import (
	"encoding/json"
)

/*
Exposes SCION path status from the Device level.

It calls the PathPool snapshot API and serializes the result as JSON.
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
			device.log.Errorf("[SCION-STATUS] failed to marshal path snapshot: %v", err)
		}
		return `{"strategy":"","pairs":[]}`
	}
	return out
}
