use anyhow::{bail, Result};
use std::fs;
use std::time::{Duration, Instant};
use super::{SERVICE_NAME, CRONTAB_FILE, collect_proc_tree, read_agent_pid, restart_cron, run_cmd};

/// Grace period before SIGKILL
const SIGTERM_GRACE: Duration = Duration::from_secs(5);

pub fn run() -> Result<()> {
    match crate::config::get("service_type").as_str() {
        "systemd"  => run_cmd("systemctl", ["stop", SERVICE_NAME]),
        "sysvinit" => sysvinit_stop(),
        t          => bail!("unknown service_type: '{t}'"),
    }
}

pub fn sysvinit_stop() -> Result<()> {
    // Remove crontab watchdog before stopping so it cannot restart the agent
    let _ = fs::remove_file(CRONTAB_FILE);
    restart_cron();

    // If the agent is already dead, stop is a no-op (idempotent)
    let root_pid = match read_agent_pid() {
        Ok(pid) => pid,
        Err(_)  => return Ok(()),
    };
    let pids = collect_proc_tree(root_pid);

    // Send SIGTERM to the process group to catch all descendants atomically
    unsafe { libc::kill(-(root_pid as libc::pid_t), libc::SIGTERM) };

    // Wait up to SIGTERM_GRACE for the root process to exit
    let deadline = Instant::now() + SIGTERM_GRACE;
    loop {
        let alive = unsafe { libc::kill(root_pid as libc::pid_t, 0) } == 0;
        if !alive { break; }
        if Instant::now() >= deadline {
            // Grace period expired — force-kill the whole group
            unsafe { libc::kill(-(root_pid as libc::pid_t), libc::SIGKILL) };
            // Fall back to individual PIDs for processes in a different group
            for &pid in &pids {
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}
