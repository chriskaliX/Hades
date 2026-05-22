//! cache/ — mirrors Go's collector/cache/ package.
//!
//! Provides shared in-memory caches populated by individual event collectors
//! and consumed cross-event (e.g. container info read by the application event).

pub mod container;
pub mod namespace;
pub mod process;
pub mod socket;
pub mod user;

use std::sync::OnceLock;

/// Cached root pid namespace inode (mirrors Go's cache.RootPns).
/// Read once from /proc/1/ns/pid at first call.
pub fn root_pns() -> u32 {
    static ROOT_PNS: OnceLock<u32> = OnceLock::new();
    *ROOT_PNS.get_or_init(|| {
        std::fs::read_link("/proc/1/ns/pid")
            .ok()
            .and_then(|p| {
                let s = p.to_string_lossy().into_owned();
                // "pid:[4026531836]" → 4026531836
                s.strip_prefix("pid:[")
                    .and_then(|s| s.strip_suffix(']'))
                    .and_then(|s| s.parse().ok())
            })
            .unwrap_or(0)
    })
}

// ── system-wide one-shot constants ─────────────────────────────────────

/// Seconds since epoch at which the system booted.
pub fn boot_time_secs() -> u64 {
    static V: OnceLock<u64> = OnceLock::new();
    *V.get_or_init(|| procfs::boot_time_secs().unwrap_or(0))
}

/// Kernel clock ticks per second (usually 100).
pub fn ticks_per_second() -> u64 {
    static V: OnceLock<u64> = OnceLock::new();
    *V.get_or_init(procfs::ticks_per_second)
}

/// Total CPU jiffies across all cores at collector startup.
/// Used to compute per-process CPU ratio matching Go's formula.
pub fn sys_time_jiffies() -> u64 {
    static V: OnceLock<u64> = OnceLock::new();
    *V.get_or_init(|| {
        let content = std::fs::read_to_string("/proc/stat").unwrap_or_default();
        content.lines().next().unwrap_or("")
            .split_whitespace()
            .skip(1)   // skip "cpu" label
            .take(8)   // user nice system idle iowait irq softirq steal
            .filter_map(|f| f.parse::<u64>().ok())
            .sum()
    })
}

/// Number of logical CPUs.
pub fn num_cpus() -> usize {
    static V: OnceLock<usize> = OnceLock::new();
    *V.get_or_init(|| {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    })
}

/// Read /proc/<pid>/ns/pid symlink and return the numeric inode as a String.
pub fn pid_ns(pid: i32) -> String {
    std::fs::read_link(format!("/proc/{pid}/ns/pid"))
        .map(|p| {
            let s = p.to_string_lossy();
            s.strip_prefix("pid:[")
                .and_then(|s| s.strip_suffix(']'))
                .unwrap_or("")
                .to_owned()
        })
        .unwrap_or_default()
}
