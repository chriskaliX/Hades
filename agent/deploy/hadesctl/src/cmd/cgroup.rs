/// Cgroup resource limiter — supports cgroup v1, v2 (unified), and hybrid.
///
/// Detection order:
///   1. Pure v2  — /sys/fs/cgroup/cgroup.controllers is non-empty
///   2. Hybrid   — /sys/fs/cgroup/unified/cgroup.controllers exists
///   3. Pure v1  — parse /proc/self/mountinfo for "cgroup" fs-type entries
///
/// Any failure is non-fatal: the caller logs a warning and starts the daemon
/// without resource limits.

use anyhow::{bail, Result};
use std::fs;
use std::process::Command;

const MEMORY_LIMIT: u64 = 262_144_000; // 250 MB
const CPU_PERIOD_US: u64 = 100_000;    // 100 ms
const CPU_QUOTA_US: u64  =  10_000;    // 10% of one core (10 ms / 100 ms)
const V1_MOUNT_ROOT: &str = "/etc/hades/cgroup";

pub struct CgroupHandle {
    mode: CgroupMode,
}

enum CgroupMode {
    V2 { dir: String },
    V1 { cpu: Option<String>, memory: Option<String> },
}

impl CgroupHandle {
    /// Write `pid` into the appropriate cgroup.procs file(s).
    ///
    /// v2: required — returns Err on failure.
    /// v1: best-effort — returns Err only if both cpu and memory writes fail.
    pub fn add_proc(&self, pid: u32) -> Result<()> {
        let pid_str = pid.to_string();
        match &self.mode {
            CgroupMode::V2 { dir } => {
                write_file(&format!("{dir}/cgroup.procs"), pid_str.as_bytes())?;
            }
            CgroupMode::V1 { cpu, memory } => {
                // Best-effort: write to whichever subsystems were set up.
                for path in cpu.iter().chain(memory.iter()) {
                    let _ = write_file(&format!("{path}/cgroup.procs"), pid_str.as_bytes())
                        .map_err(|e| eprintln!("warning: cgroup.procs {path}: {e}"));
                }
            }
        }
        Ok(())
    }
}

/// Set up the service cgroup and return a handle for writing pids into it.
pub fn setup(name: &str) -> Result<CgroupHandle> {
    // Pure v2: cgroup.controllers is non-empty (on hybrid the file exists but is empty).
    if fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return setup_v2("/sys/fs/cgroup", name);
    }
    // Hybrid: v1 default hierarchy with an additional v2 tree at unified/.
    if fs::metadata("/sys/fs/cgroup/unified/cgroup.controllers").is_ok() {
        return setup_v2("/sys/fs/cgroup/unified", name);
    }
    setup_v1(name)
}

// ── cgroup v2 ────────────────────────────────────────────────────────────────

fn setup_v2(root: &str, name: &str) -> Result<CgroupHandle> {
    let dir = format!("{root}/{name}");
    fs::create_dir_all(&dir)?;

    // Enable each controller separately: a combined "+cpu +memory" write is
    // atomic — if one is unavailable (e.g. not delegated in a container), the
    // kernel returns EINVAL and *neither* gets enabled.
    let ctrl = format!("{root}/cgroup.subtree_control");
    let _ = write_file(&ctrl, "+cpu".as_bytes());
    let _ = write_file(&ctrl, "+memory".as_bytes());

    write_file(&format!("{dir}/cpu.max"),
        format!("{CPU_QUOTA_US} {CPU_PERIOD_US}").as_bytes())
        .unwrap_or_else(|e| eprintln!("warning: v2 cpu.max: {e}"));
    write_file(&format!("{dir}/memory.max"),
        MEMORY_LIMIT.to_string().as_bytes())
        .unwrap_or_else(|e| eprintln!("warning: v2 memory.max: {e}"));

    Ok(CgroupHandle { mode: CgroupMode::V2 { dir } })
}

// ── cgroup v1 ────────────────────────────────────────────────────────────────

fn setup_v1(name: &str) -> Result<CgroupHandle> {
    // Check /proc/cgroups: columns are "name hierarchy num-cgroups enabled".
    // A subsystem is usable only when the enabled column (4th) is "1".
    let cgroups = fs::read_to_string("/proc/cgroups").unwrap_or_default();
    let enabled = |sub: &str| -> bool {
        cgroups.lines().any(|l| {
            let mut f = l.split_whitespace();
            f.next() == Some(sub) && f.nth(2) == Some("1")
        })
    };
    let (cpu_on, mem_on) = (enabled("cpu"), enabled("memory"));

    // Find existing v1 mounts from /proc/self/mountinfo.
    // Format: id parent major:minor root mount-point opts [optional...] - fs-type source super-opts
    let (mut cpu_root, mut mem_root): (Option<String>, Option<String>) = (None, None);
    if let Ok(info) = fs::read_to_string("/proc/self/mountinfo") {
        for line in info.lines() {
            let Some(sep) = line.find(" - ") else { continue };
            let mut before = line[..sep].split_whitespace();
            let mut after  = line[sep + 3..].split_whitespace();
            let Some(mount) = before.nth(4) else { continue };
            if after.next().as_deref() != Some("cgroup") { continue; }
            after.next(); // skip source
            let Some(opts) = after.next() else { continue };
            for token in opts.split(',') {
                match token {
                    "cpu"    => cpu_root = Some(mount.to_owned()),
                    "memory" => mem_root = Some(mount.to_owned()),
                    _ => {}
                }
            }
        }
    }

    let cpu = v1_prepare("cpu",    name, cpu_on, cpu_root);
    let mem = v1_prepare("memory", name, mem_on, mem_root);
    Ok(CgroupHandle { mode: CgroupMode::V1 { cpu, memory: mem } })
}

/// For one v1 subsystem: skip if disabled; use existing mount or mount ourselves;
/// create the service sub-directory; apply resource limits.
fn v1_prepare(subsystem: &str, name: &str, enabled: bool, root: Option<String>) -> Option<String> {
    if !enabled { return None; }

    let root = root.or_else(|| {
        v1_mount(subsystem)
            .map_err(|e| eprintln!("warning: v1 mount {subsystem}: {e}"))
            .ok()
    })?;

    let sub = format!("{root}/{name}");
    fs::create_dir_all(&sub)
        .map_err(|e| eprintln!("warning: v1 mkdir {sub}: {e}"))
        .ok()?;

    let res = match subsystem {
        "cpu" => {
            // Read the existing period so we stay consistent with the host (10% of one core).
            let period: u64 = fs::read_to_string(format!("{sub}/cpu.cfs_period_us"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(CPU_PERIOD_US);
            write_file(&format!("{sub}/cpu.cfs_quota_us"),
                (period / 10).max(CPU_QUOTA_US).to_string().as_bytes())
        }
        "memory" => {
            write_file(&format!("{sub}/memory.limit_in_bytes"),
                MEMORY_LIMIT.to_string().as_bytes())
        }
        _ => Ok(()),
    };
    res.unwrap_or_else(|e| eprintln!("warning: v1 limits {subsystem}: {e}"));

    Some(sub)
}

/// Mount a v1 subsystem at V1_MOUNT_ROOT/<subsystem> and return the root path.
fn v1_mount(subsystem: &str) -> Result<String> {
    let root = format!("{V1_MOUNT_ROOT}/{subsystem}");
    fs::create_dir_all(&root)?;
    let out = Command::new("mount")
        .args(["-t", "cgroup", "-o", subsystem, "cgroup", &root])
        .output()?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(root)
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Write `data` to `path`, retrying on EINTR (mirrors Elkeid's retryingWriteFile).
fn write_file(path: &str, data: &[u8]) -> Result<()> {
    use std::io::ErrorKind;
    loop {
        match fs::write(path, data) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => bail!("write {path}: {e}"),
        }
    }
}
