use anyhow::{bail, Result};
use std::fs;
use std::process::Command;
use super::{AGENT_FILE, AGENT_DIR, CGROUP_PATH, SERVICE_NAME, CRONTAB_FILE, CRONTAB_LINE, read_agent_pid, restart_cron, run_cmd};

// cgroup v1 memory limit: 250 MB
const MEMORY_LIMIT: &str = "262144000";
// CPU quota = period / 10 (10% of one core), minimum 10 ms — derived at runtime.
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub fn run() -> Result<()> {
    match crate::config::get("service_type").as_str() {
        "systemd"  => run_cmd("systemctl", ["start", SERVICE_NAME]),
        "sysvinit" => {
            sysvinit_start()?;
            // Install the cron watchdog that calls `hadesctl check` every minute.
            // Matches Elkeid start.go: write crontab + restart cron on every start.
            fs::write(CRONTAB_FILE, CRONTAB_LINE)?;
            restart_cron();
            Ok(())
        }
        t => bail!("unknown service_type: '{t}'"),
    }
}

/// Spawn hades-agent with cgroup v1 CPU + memory constraints.
pub fn sysvinit_start() -> Result<()> {
    if read_agent_pid().is_ok() {
        return Ok(()); // already running — idempotent
    }

    let cg = setup_cgroups()?;

    // Build a clean environment: only config entries + a standard PATH.
    // env_clear() prevents hadesctl's own env from leaking into the daemon.
    let cfg = crate::config::read();
    let mut cmd = Command::new(AGENT_FILE);
    cmd.current_dir(AGENT_DIR)
       .env_clear()
       .envs(&cfg)
       .env("PATH", DEFAULT_PATH);

    // setsid() detaches the agent into its own session so it survives
    // after hadesctl exits and is immune to SIGHUP.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| { libc::setsid(); Ok(()) });
    }

    let child = cmd.spawn()?;
    let pid = child.id();
    std::mem::forget(child); // daemon: never wait on it

    // Non-fatal: agent is running; missing cgroup cap is a soft degradation.
    if let Err(e) = add_to_cgroup(pid, &cg) {
        eprintln!("warning: failed to add pid {pid} to cgroup: {e}");
    }
    Ok(())
}

/// Paths to the service-specific cgroup subdirectories (cpu + memory).
struct CGroupPaths {
    cpu:    String,
    memory: String,
}

/// Ensure cgroup v1 cpu+memory subsystems are mounted and set up a service-specific
/// subdirectory for isolation (mirrors Elkeid 1.9.1 cgroup.go approach).
fn setup_cgroups() -> Result<CGroupPaths> {
    let cpu_root    = ensure_cgroup_mount("cpu")?;
    let memory_root = ensure_cgroup_mount("memory")?;

    // Create service-specific subdirectory so limits don't affect the root cgroup.
    let cpu_sub    = format!("{cpu_root}/{SERVICE_NAME}");
    let memory_sub = format!("{memory_root}/{SERVICE_NAME}");
    fs::create_dir_all(&cpu_sub)?;
    fs::create_dir_all(&memory_sub)?;

    // Derive quota from the actual period in this subsystem (10% of one core,
    // minimum 10 ms). Matches Elkeid: quota = period / 10, min 10000.
    let period: i64 = fs::read_to_string(format!("{cpu_sub}/cpu.cfs_period_us"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(100_000);
    let quota = (period / 10).max(10_000);

    fs::write(format!("{cpu_sub}/cpu.cfs_quota_us"),         quota.to_string())?;
    fs::write(format!("{memory_sub}/memory.limit_in_bytes"), MEMORY_LIMIT)?;

    Ok(CGroupPaths { cpu: cpu_sub, memory: memory_sub })
}

/// Return the root mount path for a cgroup v1 subsystem.
/// Reads /proc/self/mountinfo first; if not already mounted, creates
/// CGROUP_PATH/<subsystem> and mounts it there.
fn ensure_cgroup_mount(subsystem: &str) -> Result<String> {
    if let Some(path) = find_cgroup_mount(subsystem)? {
        return Ok(path);
    }
    let path = format!("{CGROUP_PATH}/{subsystem}");
    fs::create_dir_all(&path)?;
    let out = Command::new("mount")
        .args(["-t", "cgroup", "-o", subsystem, "cgroup", &path])
        .output()?;
    if !out.status.success() {
        bail!(
            "failed to mount cgroup {subsystem} at {path}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(path)
}

/// Parse /proc/self/mountinfo to find an existing mount point for a cgroup
/// v1 subsystem.  Returns None if no matching mount is found.
fn find_cgroup_mount(subsystem: &str) -> Result<Option<String>> {
    let info = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| anyhow::anyhow!("cannot read /proc/self/mountinfo: {e}"))?;
    for line in info.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // mountinfo field layout (kernel docs): id parent major:minor root mount-point
        //   mount-options  optional-fields  '-'  fs-type  source  super-options
        // Indices relative to the end: [-3] = fs-type, [-1] = super-options.
        if f.len() < 10 || f[f.len() - 3] != "cgroup" {
            continue;
        }
        if f[f.len() - 1].split(',').any(|s| s == subsystem) {
            return Ok(Some(f[4].to_owned())); // mount-point
        }
    }
    Ok(None)
}

fn add_to_cgroup(pid: u32, cg: &CGroupPaths) -> Result<()> {
    let s = pid.to_string();
    // cgroup.procs moves the entire thread group atomically (safer than tasks).
    fs::write(format!("{}/cgroup.procs", cg.cpu),    &s)?;
    fs::write(format!("{}/cgroup.procs", cg.memory), &s)?;
    Ok(())
}
