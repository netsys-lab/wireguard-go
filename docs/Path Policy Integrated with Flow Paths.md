# Path Policy Integrated with Flow Paths

The Path Policy engine now filters and sorts SCION paths when the user taps a flow in the Android UI — the "Paths for Flows" feature uses the same policy machinery that was previously only wired into the Translator for packet-level path selection.

## Top-Down Flow

```
User taps SCION flow in TunnelDetailFragment
    ↓
PathSelectionBottomSheet opens, calls FlowRepository.getFlowPaths(tunnel, flowId)
    ↓
JNI bridge → GoBackend.getFlowPaths() → wgGetFlowPaths() in api-android.go
    ↓
device.SCIONPathsForFlow(flowID)
    ↓
    1. Lookup flow snapshot from flow.Manager.GetByID()
    2. Lookup SCIONEgressState (SrcIA, DstIA) for that flow
    3. Get cached paths from PathPool.GetCached(SrcIA, DstIA)
    4. Apply PathPolicy engine: engine.SelectPaths(info, paths)
         ↓
        a. MatchPacket() — match flow attributes to a policy name
        b. FilterPaths() — ACL, sequence, requirements
        c. SortPaths() — by ordering rules
        d. Failover chain if no paths survive
         ↓
    5. Mark first surviving path as "current" (currentPathIndex = 0)
    6. Build FlowPathDTOs with policy metadata
    7. Return FlowPathsResult JSON to Android
    ↓
Android renders path list in RecyclerView, shows "CURRENT PATH" badge
```

## Changes Made

### wireguard-go

**device/device.go**
- Added `policyEngine *pathpolicy.Engine` field to `Device` struct
- In `InitSCION()`, after loading the policy engine from disk, stored it on `device.policyEngine` (previously only passed to translator)
- `SCIONPathsForFlow()` now calls `device.policyEngine.SelectPaths(info, paths)` to filter and sort paths before returning them to the UI
- Added `buildPacketInfo()` helper to construct `pathpolicy.PacketInfo` from the flow snapshot (SrcIA, DstIA, SrcIP/Port, DstIP/Port, Protocol)
- Added `protocolName()` helper to convert IP protocol numbers to strings ("tcp"/"udp")
- Fixed two `scionLog.Verbosef()` calls → `scionLog.Infof()` (scionlog has no Verbosef method)

**device/scion_flow_state.go**
- Added `PolicyName string` field to `FlowPathsResult` JSON DTO

**device/scion_config.go**
- Fixed formatting of `PolicyFile` field in `ScionDeviceConfig` struct (mixed tabs/spaces caused parser errors)

**translator/pathpolicy/engine.go**
- Added `Matchers() []Matcher` accessor method on `Engine` for external `MatchPacket` calls

### wireguard-android

**ui/.../model/FlowModels.kt**
- Added `policyName: String?` field to `FlowPathsResponseDto`
- Updated `parseFlowPathsResponse()` to read `policyName` from JSON

### Not Changed (By Design)

- **send.go**: The policy engine is stateless — it does not need to be "notified" of path changes. It operates on whatever paths are passed to `SelectPaths()`. The Translator already uses the engine per-packet in `selectPathWithPolicy()`.
- **flow/manager.go**: The flow manager remains purely observational. Policy is a UI/display concern and is applied at the device layer in `SCIONPathsForFlow()`, not in the flow accounting pipeline.
- **currentPathIndex()**: Always returns 0, which is correct: after policy filtering/sorting, the first path in the result array is the policy-selected "best" path.

### Frontend Compatibility

The Android frontend (`wireguard-android`, branch `develop`) receives the path list already filtered and sorted by policy. The `policyName` field in the JSON response allows the UI to display which policy was applied. The `current: true` flag on the first path tells the frontend which path is currently active.

No changes are needed to the Android path selection bottom sheet for the policy integration to work — it already handles the `current` flag and renders path data. The `policyName` is available for future UI enhancement (e.g., showing "Policy: low-latency" in the sheet header).

### Build Verification

```
go build ./...       → OK
go test ./flow/...   → OK
go test ./device/... → OK
```
