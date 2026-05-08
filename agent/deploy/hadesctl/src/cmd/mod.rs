pub mod check;
pub mod cgroup;
pub mod disable;
pub mod enable;
pub mod reload;
pub mod restart;
pub mod set;
pub mod start;
pub mod status;
pub mod stop;

// ── shared constants ────────────────────────────────────────────────────────

pub const SERVICE_NAME: &str = "hades-agent";
pub const SERVICE_FILE: &str = "/etc/hades/hades-agent.service";
pub const AGENT_FILE:   &str = "/etc/hades/hades-agent";
pub const AGENT_DIR:    &str = "/etc/hades";
/// PID directory — must match agent's `PIDPATH` constant in `agent/mod.rs`
pub const PIDPATH:      &str = "/var/run/";
pub const CRONTAB_FILE: &str = "/etc/cron.d/hades-agent";
/// Cron job that calls `hadesctl check` every minute (watchdog)
pub const CRONTAB_LINE: &str = "* * * * * root /etc/hades/hadesctl check\n";

// ── helpers ─────────────────────────────────────────────────────────────────

use std::process::Command;

/// Run a command, inheriting stdout/stderr; bail on non-zero exit.
pub fn run_cmd<I>(program: &str, args: I) -> anyhow::Result<()>
where
    I: IntoIterator,
    I::Item: AsRef<std::ffi::OsStr>,
{
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run {program}: {e}"))?;
    if !status.success() {
        anyhow::bail!("{program} exited with {status}");
    }
    Ok(())
}

/// Check whether `cmd` is reachable via `$PATH` — equivalent to Go's
/// `exec.LookPath`.  Falls back to common sbin/bin dirs if `PATH` is unset.
pub fn has_cmd(cmd: &str) -> bool {
    let path_var = std::env::var("PATH").unwrap_or_else(|_| {
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into()
    });
    path_var
        .split(':')
        .any(|dir| std::path::Path::new(dir).join(cmd).exists())
}

/// Read the PID written by hades-agent.
/// Path is derived from `PIDPATH` + `SERVICE_NAME` + `.pid`, matching the
/// agent's own `acquire_pid_lock` logic in `main.rs`.
pub fn read_agent_pid() -> anyhow::Result<u32> {
    let pid_path = format!("{PIDPATH}{SERVICE_NAME}.pid");
    let content = std::fs::read_to_string(&pid_path)
        .map_err(|e| anyhow::anyhow!("cannot read pid file {pid_path}: {e}"))?;
    let pid: i32 = content
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid pid in {pid_path}"))?;
    if pid <= 0 {
        anyhow::bail!("invalid pid value {pid} in {pid_path}");
    }
    // kill(pid, 0) — existence check only.
    // rc == 0  → process alive and we can signal it
    // rc == -1, EPERM  → process alive but we lack permission (treat as alive)
    // rc == -1, ESRCH  → process does not exist
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EPERM) {
            anyhow::bail!("process {pid} is not running: {err}");
        }
    }
    Ok(pid as u32)
}

/// Collect the cgroup-v1 process list from the service's `cgroup.procs`.
/// Falls back to `/proc` walk if the cgroup is unavailable.
pub fn collect_proc_tree(root_pid: u32) -> Vec<u32> {
    // pids_from_cgroup() already returns Err on empty, so Ok(_) is non-empty.
    if let Ok(pids) = pids_from_cgroup() {
        return pids;
    }
    pids_from_proc(root_pid)
}

fn pids_from_cgroup() -> anyhow::Result<Vec<u32>> {
    let procs = find_service_cgroup_procs()?;
    let content = std::fs::read_to_string(&procs)?;
    let pids: Vec<u32> = content
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .filter(|&p| p > 1)
        .collect();
    if pids.is_empty() {
        anyhow::bail!("empty cgroup.procs");
    }
    Ok(pids)
}

/// Locate the service-specific `cgroup.procs` file.
/// Checks our own mount path first, then walks /proc/self/mountinfo for any
/// system-level cpu cgroup that contains the service subdirectory.
fn find_service_cgroup_procs() -> anyhow::Result<String> {
    // Fast path: we mounted it ourselves (v1 fallback path)
    let own = format!("/etc/hades/cgroup/cpu/{SERVICE_NAME}/cgroup.procs");
    if std::path::Path::new(&own).exists() {
        return Ok(own);
    }
    // Slow path: system already had the cpu cgroup mounted elsewhere
    let info = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| anyhow::anyhow!("cannot read /proc/self/mountinfo: {e}"))?;
    for line in info.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 || f[f.len() - 3] != "cgroup" {
            continue;
        }
        if f[f.len() - 1].split(',').any(|s| s == "cpu") {
            let candidate = format!("{}/{SERVICE_NAME}/cgroup.procs", f[4]);
            if std::path::Path::new(&candidate).exists() {
                return Ok(candidate);
            }
        }
    }
    anyhow::bail!("service cgroup not found")
}

/// Restart cron daemon.
/// Both commands are attempted; `service` returns non-zero when the service
/// does not exist, and the error is intentionally ignored — matching the
/// Elkeid reference implementation.  On Debian/Ubuntu only `cron` succeeds;
/// on RHEL/CentOS only `crond` succeeds.
pub fn restart_cron() {
    let _ = Command::new("service").args(["cron",  "restart"]).status();
    let _ = Command::new("service").args(["crond", "restart"]).status();
}

fn pids_from_proc(root_pid: u32) -> Vec<u32> {
    use std::fs;
    let mut result = vec![root_pid];
    // Walk /proc to find all descendants of root_pid
    let Ok(entries) = fs::read_dir("/proc") else {
        return result;
    };
    let mut children: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        // /proc entries are plain ASCII digits; to_str() avoids Cow allocation.
        let Ok(pid) = name.to_str().unwrap_or("").parse::<u32>() else {
            continue;
        };
        if pid <= 1 { continue; }
        let status_path = format!("/proc/{pid}/status");
        let Ok(status) = fs::read_to_string(status_path) else {
            continue;
        };
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("PPid:") {
                if let Ok(ppid) = rest.trim().parse::<u32>() {
                    children.entry(ppid).or_default().push(pid);
                }
                break;
            }
        }
    }
    // BFS from root_pid
    let mut queue = std::collections::VecDeque::from([root_pid]);
    while let Some(pid) = queue.pop_front() {
        if let Some(kids) = children.get(&pid) {
            for &kid in kids {
                result.push(kid);
                queue.push_back(kid);
            }
        }
    }
    result
}
