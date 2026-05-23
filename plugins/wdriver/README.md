# wdriver

`wdriver` is the Windows Rust plugin track for Hades. It is intended to align
with the Hades-Windows C++ service/plugin semantics while keeping the transport
protocol unchanged.

## Current Scope

- Plugin transport uses Windows stdin/stdout framing: `uint32 little-endian length + protobuf payload`.
- Reports are encoded as `Record { data_type, timestamp, data.fields }`.
- Windows event payload keeps the existing server convention: `fields["data_type"]` and `fields["udata"]`.
- Task acknowledgements use data type `5100` with `token`, `status`, and `msg`.

## Phase 1 Collection

The current minimal loop supports server-triggered collection tasks:

- `200`: process snapshot
- `202`: autorun registry snapshot
- `203`: network socket snapshot
- `207`: local account snapshot
- `208`: installed software snapshot

The field names intentionally match the existing Hades-Linux Windows handlers
and Hades-Windows C++ reports. Keep the outer protocol stable; future expansion
should add fields inside `udata` instead of changing the transport frame or
top-level `Record` semantics.

## ETW Direction

ETW should be implemented as active reporting: after startup or explicit task
enablement, the plugin owns the ETW session and pushes events to stdout without
waiting for a polling task. This should follow the same `Record + udata` shape
used by the C++ path:

- `300`: process ETW
- `301`: thread ETW
- `302`: image load ETW
- `303`: network ETW
- `304`: registry ETW
- `305`: file I/O ETW

Keep ETW session start/stop, callback dispatch, and report throttling isolated
from the task collection loop so task handling cannot block active event upload.

## Relationship To Hades-Windows

The Rust plugin is not a rewrite of the full Windows C++ service yet. The
long-term goal is to gradually align with these Hades-Windows components:

- `HadSvc`: service/plugin orchestration and report transport
- `MonitorEvent/sysmonuserlib`: user-mode collection and ETW
- `MonitorEvent/sysmondrvlib`: kernel monitor bridge
- `MonitorEvent/netdrvlib`: kernel network bridge
- `RuleEngineSvc`: rule evaluation and blocking semantics

Driver and blocking capabilities should be added only after the reporting
semantics are stable and compatible with the server handlers.
