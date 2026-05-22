/// Per-plugin status metric (data_type = 2 / DTPluginStatus).
///
/// Mirrors Go's `metrics/metric_plugin.go`.
///
/// This module is intentionally a stub until the `plugin` manager is
/// implemented: the `PLUGIN_ITER` hook below will be populated by the
/// plugin module once it exists.  Until then `flush` is a no-op.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use super::IMetric;

// ── Plugin iterator hook ───────────────────────────────────────────────────────
//
// The plugin manager will register a function here that yields snapshots of
// all live plugins.  Keeping the coupling to a simple function pointer avoids
// a circular dependency between the metrics and plugin modules.

pub struct PluginSnapshot {
    pub name:        String,
    pub version:     String,
    pub pid:         u32,
    pub workdir:     String,
    pub rx_speed:    f64,
    pub tx_speed:    f64,
    pub rx_tps:      f64,
    pub tx_tps:      f64,
}

/// Type alias for the iterator callback registered by the plugin module.
type PluginIterFn = fn() -> Vec<PluginSnapshot>;

static PLUGIN_ITER: std::sync::OnceLock<PluginIterFn> = std::sync::OnceLock::new();

/// Called once by the plugin module during its initialisation to register
/// the snapshot iterator.  Idempotent — subsequent calls are ignored.
pub fn register_iter(f: PluginIterFn) {
    let _ = PLUGIN_ITER.set(f);
}

/// Returns snapshots of all currently live plugins, or an empty vec if the
/// plugin module has not yet registered an iterator.
pub fn iter_snapshots() -> Vec<PluginSnapshot> {
    PLUGIN_ITER.get().map(|f| f()).unwrap_or_default()
}

// ── Cached totals (updated by PluginMetric::flush, read by AgentMetric) ────────
//
// These atomics let AgentMetric include all-plugin CPU+RSS in the agent
// heartbeat without re-sampling /proc (which would reset PROC_CACHE deltas
// and give PluginMetric near-zero CPU readings).
static PLUGIN_CPU_TOTAL_BITS: AtomicU64 = AtomicU64::new(0);
static PLUGIN_RSS_TOTAL:      AtomicU64 = AtomicU64::new(0);

/// Returns the most-recently computed (cpu_fraction_sum, rss_bytes_sum) for
/// all live plugins.  Called by AgentMetric every flush cycle.
pub fn last_plugin_totals() -> (f64, u64) {
    let cpu = f64::from_bits(PLUGIN_CPU_TOTAL_BITS.load(Ordering::Relaxed));
    let rss = PLUGIN_RSS_TOTAL.load(Ordering::Relaxed);
    (cpu, rss)
}

// ── PluginMetric ────────────────────────────────────────────────────────────

const DT_PLUGIN_STATUS: i32 = 2;

pub struct PluginMetric;

impl IMetric for PluginMetric {
    fn name(&self) -> &'static str { "plugin" }
    fn init(&self) -> anyhow::Result<()> { Ok(()) }

    fn flush(&self, _now: Instant) {
        use std::collections::HashMap;
        use crate::{
            proto::{Payload, Record},
            transport::transfer::trans,
        };
        use super::resource;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let iter = match PLUGIN_ITER.get() {
            Some(f) => f,
            None    => return, // plugin module not yet initialised
        };

        let mut total_cpu = 0.0_f64;
        let mut total_rss = 0_u64;

        for snap in iter() {
            let (cpu_str, rss_str, rs_str, ws_str, nfd_str, start_at_str) =
                match resource::sample(snap.pid) {
                    Some(r) => {
                        total_cpu += r.cpu;
                        total_rss += r.rss;
                        (
                            format!("{:.8}", r.cpu),
                            r.rss.to_string(),
                            format!("{:.8}", r.read_speed),
                            format!("{:.8}", r.write_speed),
                            r.fds.to_string(),
                            r.start_at.to_string(),
                        )
                    }
                    None => (
                        "0.00000000".to_owned(),
                        "0".to_owned(),
                        "0.00000000".to_owned(),
                        "0.00000000".to_owned(),
                        "0".to_owned(),
                        "0".to_owned(),
                    ),
                };

            let du = resource::dir_size(std::path::Path::new(&snap.workdir), "");

            let fields: HashMap<String, String> = [
                ("name",        snap.name.clone()),
                ("pversion",    snap.version.clone()),
                ("pid",         snap.pid.to_string()),
                ("cpu",         cpu_str),
                ("rss",         rss_str),
                ("read_speed",  rs_str),
                ("write_speed", ws_str),
                ("nfd",         nfd_str),
                ("start_at",    start_at_str),
                ("rx_tps",      format!("{:.8}", snap.rx_tps)),
                ("tx_tps",      format!("{:.8}", snap.tx_tps)),
                ("rx_speed",    format!("{:.8}", snap.rx_speed)),
                ("tx_speed",    format!("{:.8}", snap.tx_speed)),
                ("du",          du.to_string()),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();

            let rec = Record {
                data_type: DT_PLUGIN_STATUS,
                timestamp: ts,
                data: Some(Payload { fields }),
            };
            // Keep plugin status records under pressure so performance lines stay continuous.
            let _ = trans().transmission(rec, true);
        }

        // Update cached totals for AgentMetric to include in agent heartbeat.
        PLUGIN_CPU_TOTAL_BITS.store(total_cpu.to_bits(), Ordering::Relaxed);
        PLUGIN_RSS_TOTAL.store(total_rss, Ordering::Relaxed);
    }
}
