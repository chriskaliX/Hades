/// Periodic metrics collection — mirrors Go's `agent/metrics/` package.
///
/// Module layout:
///   mod.rs      — `IMetric` trait, registry, `startup` loop
///   resource.rs — per-process CPU/RSS/IO/FD from `/proc`
///   host.rs     — hostname & IP refresh (writes `agent::host`)
///   agent.rs    — agent-level heartbeat (data_type = 1)
///   plugin.rs   — per-plugin status (data_type = 2)
pub mod agent;
pub mod host;
pub mod plugin;
pub mod resource;

use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Shared metric interface — mirrors `IMetric` in Go.
pub trait IMetric: Send + Sync {
    fn name(&self) -> &'static str;
    /// Called once at startup. Return `Err` to skip the initial flush.
    fn init(&self) -> anyhow::Result<()>;
    /// Flush one sample.  `now` is the `Instant` the tick fired.
    fn flush(&self, now: Instant);
}

/// Start the metrics collection loop (one sample per minute).
///
/// `init()` metrics are flushed once at startup before the loop begins.
pub async fn startup(token: CancellationToken) {
    log::info!("metrics starts");

    // Build registry — order matches Go's `init()` execution order.
    let metrics: Vec<Box<dyn IMetric>> = vec![
        Box::new(host::HostMetric),
        Box::new(agent::AgentMetric::new()),
        Box::new(plugin::PluginMetric),
    ];

    // Init-time flush
    let now = Instant::now();
    for m in &metrics {
        match m.init() {
            Ok(()) => m.flush(now),
            Err(e) => log::error!("metrics {} init failed: {e:#}", m.name()),
        }
    }

    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first tick fires immediately — skip it so we don't double-flush init metrics.
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            t = ticker.tick() => {
                let now = t.into_std();
                for m in &metrics {
                    m.flush(now);
                }
            }
        }
    }
    log::info!("metrics exits");
}
