use std::{collections::HashMap, path::Path, time::Instant};
use procfs::prelude::*;

use crate::{
    agent,
    proto::{Payload, Record},
    transport::{connection::stats_handler, transfer::trans},
};
use super::{plugin, resource, IMetric};

const DT_AGENT_STATUS: i32 = 1;

#[derive(Default)]
pub struct AgentMetric {
    // Static fields, populated once in `new()`.
    kernel_version:   String,
    arch:             String,
    platform:         String,
    platform_family:  String,
    platform_version: String,
    cpu_num:          String,
    cpu_logical_num:  String,
    cpu_mhz:          String,
    cpu_name:         String,
    boot_at:          String,
    total_memory:     u64,
    pid:              u32,   // process ID is fixed for the agent's lifetime
}

impl AgentMetric {
    /// Collect immutable host facts once at construction.
    pub fn new() -> Self {
        let (platform, platform_family, platform_version) = os_release();
        let (physc, logicc, mhz, cpu_name) = cpu_info();
        Self {
            kernel_version:   std::fs::read_to_string("/proc/sys/kernel/osrelease")
                                  .map(|s| s.trim().to_owned())
                                  .unwrap_or_default(),
            arch:             std::env::consts::ARCH.to_owned(),
            platform,
            platform_family,
            platform_version,
            cpu_num:          physc.to_string(),
            cpu_logical_num:  logicc.to_string(),
            cpu_mhz:          mhz,
            cpu_name,
            boot_at:          procfs::boot_time_secs()
                                  .map(|t| t.to_string())
                                  .unwrap_or_else(|_| "0".to_owned()),
            total_memory:     procfs::Meminfo::current().map(|m| m.mem_total).unwrap_or(0),
            pid:              std::process::id(),
        }
    }
}

impl IMetric for AgentMetric {
    fn name(&self) -> &'static str { "agent" }
    fn init(&self) -> anyhow::Result<()> { Ok(()) }

    fn flush(&self, _now: Instant) {
        let ts = unix_ts();

        let (mut cpu_total, mut rss_total, rs_str, ws_str, nfd_str, start_at_str) =
            match resource::sample(self.pid) {
                Some(r) => (
                    r.cpu,
                    r.rss,
                    format!("{:.8}", r.read_speed),
                    format!("{:.8}", r.write_speed),
                    r.fds.to_string(),
                    r.start_at.to_string(),
                ),
                None => (0.0, 0, "0.00000000".into(), "0.00000000".into(), "0".into(), "0".into()),
            };

        for snap in plugin::iter_snapshots() {
            if let Some(r) = resource::sample(snap.pid) {
                cpu_total += r.cpu;
                rss_total += r.rss;
            }
        }

        let gstats                 = stats_handler().get_stats();
        let (tx_tps, rx_tps)       = trans().get_state();
        let du                     = resource::dir_size(Path::new(&*agent::WORKDIR), "plugin");
        let (state, state_detail)  = agent::state::get();
        let (load1, load5, load15) = procfs::LoadAverage::current()
            .map(|l| (l.one as f64, l.five as f64, l.fifteen as f64))
            .unwrap_or_default();
        let sys_mem = procfs::Meminfo::current()
                .map(|m| {
                    let avail = m.mem_available.unwrap_or(0);
                    self.total_memory.saturating_sub(avail) as f64 / self.total_memory.max(1) as f64 * 100.0
                })
                .unwrap_or(0.0);

        // Build the flat fields map: static fields from `self` + freshly computed dynamic fields.
        let mut fields = HashMap::<String, String>::with_capacity(32);
        // Static (populated once in new())
        fields.insert("kernel_version".to_owned(),   self.kernel_version.clone());
        fields.insert("arch".to_owned(),             self.arch.clone());
        fields.insert("platform".to_owned(),         self.platform.clone());
        fields.insert("platform_family".to_owned(),  self.platform_family.clone());
        fields.insert("platform_version".to_owned(), self.platform_version.clone());
        fields.insert("cpu_num".to_owned(),          self.cpu_num.clone());
        fields.insert("cpu_logical_num".to_owned(),  self.cpu_logical_num.clone());
        fields.insert("cpu_mhz".to_owned(),          self.cpu_mhz.clone());
        fields.insert("cpu_name".to_owned(),         self.cpu_name.clone());
        fields.insert("boot_at".to_owned(),          self.boot_at.clone());
        fields.insert("total_memory".to_owned(),     self.total_memory.to_string());
        fields.insert("nproc".to_owned(),            self.cpu_logical_num.clone());
        // Dynamic (refreshed every flush)
        fields.insert("pid".to_owned(),         self.pid.to_string());
        fields.insert("cpu".to_owned(),         format!("{:.8}", cpu_total));
        fields.insert("rss".to_owned(),         rss_total.to_string());
        fields.insert("read_speed".to_owned(),  rs_str);
        fields.insert("write_speed".to_owned(), ws_str);
        fields.insert("nfd".to_owned(),         nfd_str);
        fields.insert("start_at".to_owned(),    start_at_str);
        fields.insert("tx_speed".to_owned(),    format!("{:.8}", gstats.tx_speed));
        fields.insert("rx_speed".to_owned(),    format!("{:.8}", gstats.rx_speed));
        fields.insert("tx_tps".to_owned(),      format!("{:.8}", tx_tps));
        fields.insert("rx_tps".to_owned(),      format!("{:.8}", rx_tps));
        fields.insert("du".to_owned(),          du.to_string());
        fields.insert("ngr".to_owned(),         procfs::process::Process::myself()
            .and_then(|p| p.status())
            .map(|s| s.threads.to_string())
            .unwrap_or_else(|_| "1".to_owned()));
        fields.insert("state".to_owned(),       state);
        fields.insert("state_detail".to_owned(),state_detail);
        fields.insert("sys_cpu".to_owned(),     format!("{:.8}", sys_cpu_percent()));
        fields.insert("sys_mem".to_owned(),     format!("{:.8}", sys_mem));
        fields.insert("load_1".to_owned(),      format!("{:.2}", load1));
        fields.insert("load_5".to_owned(),      format!("{:.2}", load5));
        fields.insert("load_15".to_owned(),     format!("{:.2}", load15));

        let _ = trans().transmission(
            Record {
                data_type: DT_AGENT_STATUS,
                timestamp: ts,
                data: Some(Payload { fields }),
            },
            false,
        );
    }
}

fn unix_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parse `/etc/os-release` → (platform, platform_family, platform_version).
///
/// Reads the file once and extracts `ID`, `ID_LIKE`, and `VERSION_ID` in a
/// single pass, replacing the `os_info` crate entirely.
fn os_release() -> (String, String, String) {
    use std::io::BufRead;
    let (mut id, mut id_like, mut version_id) = (String::new(), String::new(), String::new());
    if let Ok(f) = std::fs::File::open("/etc/os-release") {
        for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
            if let Some(v) = line.strip_prefix("ID=") {
                id = v.trim_matches('"').to_owned();
            } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
                // ID_LIKE may be space-separated (e.g. "rhel fedora"); take first token.
                id_like = v.trim_matches('"')
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_owned();
            } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
                version_id = v.trim_matches('"').to_owned();
            }
        }
    }
    let family = if id_like.is_empty() { id.clone() } else { id_like };
    (id, family, version_id)
}

fn cpu_info() -> (usize, usize, String, String) {
    use std::collections::HashSet;
    let Ok(info) = procfs::CpuInfo::current() else {
        return (1, 1, "0.0".to_owned(), String::new());
    };

    let logical = info.cpus.len();
    let physical_ids: HashSet<u32> = info.cpus.iter()
        .filter_map(|cpu| cpu.get("physical id")?.parse().ok())
        .collect();
    let physical = if physical_ids.is_empty() { logical } else { physical_ids.len() };

    let (mhz_sum, mhz_count): (f64, usize) = info.cpus.iter()
        .filter_map(|cpu| cpu.get("cpu MHz")?.parse::<f64>().ok())
        .fold((0.0, 0), |(s, n), f| (s + f, n + 1));
    let avg_ghz = if mhz_count > 0 {
        format!("{:.1}", mhz_sum / mhz_count as f64 / 1000.0)
    } else {
        "0.0".to_owned()
    };

    let model_name = info.cpus.first()
        .and_then(|cpu| cpu.get("model name"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();

    (physical, logical, avg_ghz, model_name)
}

fn sys_cpu_percent() -> f64 {
    struct Snap { idle: u64, total: u64 }
    static LAST: parking_lot::Mutex<Option<Snap>> = parking_lot::Mutex::new(None);

    let (idle, total) = match procfs::KernelStats::current() {
        Ok(ks) => {
            let c = &ks.total;
            let idle  = c.idle + c.iowait.unwrap_or(0);
            let total = c.user + c.nice + c.system + c.idle
                + c.iowait.unwrap_or(0) + c.irq.unwrap_or(0)
                + c.softirq.unwrap_or(0) + c.steal.unwrap_or(0);
            (idle, total)
        }
        Err(_) => (0, 0),
    };

    let mut guard = LAST.lock();
    let pct = match guard.as_ref() {
        Some(prev) => {
            let dt = total.saturating_sub(prev.total);
            let di = idle.saturating_sub(prev.idle);
            if dt > 0 { (1.0 - di as f64 / dt as f64) * 100.0 } else { 0.0 }
        }
        None => 0.0,
    };
    *guard = Some(Snap { idle, total });
    pct
}

