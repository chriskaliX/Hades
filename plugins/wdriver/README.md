# wdriver

`wdriver` is the Windows Rust plugin track for Hades. It is intended to align
with the Hades-Windows C++ service/plugin semantics while keeping the transport
protocol unchanged.

`wdriver` 是 Hades 的 Windows Rust 插件方向，用于逐步对齐
Hades-Windows C++ 服务/插件语义，同时保持现有传输协议不变。

## Current Scope / 当前范围

- Plugin transport uses Windows stdin/stdout framing: `uint32 little-endian length + protobuf payload`.
- 插件传输使用 Windows stdin/stdout 帧格式：`uint32 小端长度 + protobuf payload`。
- Reports are encoded as `Record { data_type, timestamp, data.fields }`.
- 上报数据编码为 `Record { data_type, timestamp, data.fields }`。
- Windows event payload keeps the existing server convention: `fields["data_type"]` and `fields["udata"]`.
- Windows 事件载荷保持 server 现有约定：`fields["data_type"]` 和 `fields["udata"]`。
- Task acknowledgements use data type `5100` with `token`, `status`, and `msg`.
- 任务回执使用数据类型 `5100`，字段为 `token`、`status`、`msg`。

## Phase 1 Collection / 一期采集

The current minimal loop supports server-triggered collection tasks:

当前最小闭环支持 server 下发触发的采集任务：

- `200`: process snapshot / 进程快照
- `202`: autorun registry snapshot / 自启动注册表快照
- `203`: network socket snapshot / 网络连接快照
- `207`: local account snapshot / 本地账户快照
- `208`: installed software snapshot / 已安装软件快照

The field names intentionally match the existing Hades-Linux Windows handlers
and Hades-Windows C++ reports. Keep the outer protocol stable; future expansion
should add fields inside `udata` instead of changing the transport frame or
top-level `Record` semantics.

字段名刻意保持与 Hades-Linux Windows handler 和 Hades-Windows C++ 上报一致。
外层协议需要保持稳定；后续扩展优先在 `udata` 内增加字段，不改变传输帧或
顶层 `Record` 语义。

## ETW Direction / ETW 方向

ETW should be implemented as active reporting: after startup or explicit task
enablement, the plugin owns the ETW session and pushes events to stdout without
waiting for a polling task. This should follow the same `Record + udata` shape
used by the C++ path:

ETW 应按主动上报实现：插件启动或收到显式启用任务后，由插件持有 ETW session，
并主动向 stdout 推送事件，不依赖轮询任务。上报结构应继续沿用 C++ 链路的
`Record + udata` 形态：

- `300`: process ETW / 进程 ETW
- `301`: thread ETW / 线程 ETW
- `302`: image load ETW / 镜像加载 ETW
- `303`: network ETW / 网络 ETW
- `304`: registry ETW / 注册表 ETW
- `305`: file I/O ETW / 文件 I/O ETW

Keep ETW session start/stop, callback dispatch, and report throttling isolated
from the task collection loop so task handling cannot block active event upload.

ETW session 启停、回调分发、上报限速应与任务采集循环隔离，避免任务处理阻塞
主动事件上报。

## Relationship To Hades-Windows / 与 Hades-Windows 的关系

The Rust plugin is not a rewrite of the full Windows C++ service yet. The
long-term goal is to gradually align with these Hades-Windows components:

当前 Rust 插件还不是完整 Windows C++ 服务的重写版本。长期目标是逐步对齐以下
Hades-Windows 组件能力：

- `HadSvc`: service/plugin orchestration and report transport / 服务、插件编排与上报传输
- `MonitorEvent/sysmonuserlib`: user-mode collection and ETW / 用户态采集与 ETW
- `MonitorEvent/sysmondrvlib`: kernel monitor bridge / 内核监控桥接
- `MonitorEvent/netdrvlib`: kernel network bridge / 内核网络桥接
- `RuleEngineSvc`: rule evaluation and blocking semantics / 规则评估与阻断语义

Driver and blocking capabilities should be added only after the reporting
semantics are stable and compatible with the server handlers.

驱动和阻断能力应在上报语义稳定、且与 server handler 兼容后再逐步补齐。
