/// Per-process resource sampling from `/proc/<pid>/`.
///
/// Mirrors Go's `metrics/resource.go` (getProcResource / getDirSize).
/// All sampling is synchronous and cheap enough to run in an async context.
use procfs::prelude::*;
use procfs::process::Process;
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{Mutex, OnceLock},
    time::Instant,
};

/// Clock ticks per second — determined at boot, never changes.
fn ticks() -> f64 {
    static TICKS: OnceLock<f64> = OnceLock::new();
    *TICKS.get_or_init(|| procfs::ticks_per_second() as f64)
}

/// Boot time (Unix epoch seconds) from `/proc/stat btime` — integer, no float drift.
fn boot_time() -> i64 {
    static BOOT: OnceLock<i64> = OnceLock::new();
    *BOOT.get_or_init(|| {
        procfs::KernelStats::current()
            .map(|ks| ks.btime as i64)
            .unwrap_or(0)
    })
}

pub struct ProcResource {
    /// CPU usage fraction (0.0 – N.0 for N cores), delta since last call.
    pub cpu:         f64,
    /// Resident-set size in bytes.
    pub rss:         u64,
    /// Read throughput in bytes / second since last call.
    pub read_speed:  f64,
    /// Write throughput in bytes / second since last call.
    pub write_speed: f64,
    /// Number of open file descriptors.
    pub fds:         i32,
    /// Process start time (Unix epoch seconds).
    pub start_at:    i64,
}

// A cache that tracks I/O bytes AND cpu ticks between samples.
struct ProcState {
    time:        Instant,
    read_bytes:  u64,
    write_bytes: u64,
    cpu_ticks:   u64,
}

static PROC_CACHE: Mutex<Option<HashMap<u32, ProcState>>> = Mutex::new(None);

/// Full resource sample: CPU fraction, RSS, I/O speeds, FD count, start time.
/// Returns `None` if `/proc/<pid>` is not readable (process gone).
pub fn sample(pid: u32) -> Option<ProcResource> {
    let now     = Instant::now();
    let ticks   = ticks();
    let proc    = Process::new(pid as i32).ok()?;
    let stat    = proc.stat().ok()?;

    let cur_ticks = stat.utime + stat.stime;
    let rss       = proc.status().ok().and_then(|s| s.vmrss).unwrap_or(0) * 1024;
    let fds       = proc.fd_count().unwrap_or(0) as i32;
    let start_at  = boot_time() + (stat.starttime as f64 / ticks) as i64;
    let (rb, wb)  = proc.io().ok()
        .map(|io| (io.read_bytes, io.write_bytes))
        .unwrap_or((0, 0));

    // Single lock: read prev, compute deltas, write new state.
    let (cpu, read_speed, write_speed) = {
        let mut guard = PROC_CACHE.lock().unwrap();
        let map = guard.get_or_insert_with(HashMap::new);

        let result = match map.get(&pid) {
            Some(prev) => {
                let dt = now.duration_since(prev.time).as_secs_f64().max(f64::MIN_POSITIVE);
                (
                    (cur_ticks.saturating_sub(prev.cpu_ticks)) as f64 / (dt * ticks),
                    rb.saturating_sub(prev.read_bytes)  as f64 / dt,
                    wb.saturating_sub(prev.write_bytes) as f64 / dt,
                )
            }
            None => {
                // First sample — spread over the process's entire lifetime so far.
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let age = (now_secs - start_at).max(1) as f64;
                (
                    cur_ticks as f64 / (age * ticks),
                    rb as f64 / age,
                    wb as f64 / age,
                )
            }
        };

        map.insert(pid, ProcState { time: now, read_bytes: rb, write_bytes: wb, cpu_ticks: cur_ticks });
        result
    };

    Some(ProcResource { cpu, rss, read_speed, write_speed, fds, start_at })
}

/// Recursively sum file sizes under `path`, skipping any sub-directory named
/// exactly `except` (mirrors Go's `getDirSize`).
pub fn dir_size(path: &Path, except: &str) -> u64 {
    fn walk(p: &Path, except: &str, acc: &mut u64) {
        let Ok(rd) = fs::read_dir(p) else { return };
        for entry in rd.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                let name = entry.file_name();
                if !except.is_empty() && name == except { continue; }
                walk(&entry.path(), except, acc);
            } else {
                *acc += meta.len();
            }
        }
    }
    let mut total = 0u64;
    walk(path, except, &mut total);
    total
}
