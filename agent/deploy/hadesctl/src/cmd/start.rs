use anyhow::{bail, Result};
use std::fs;
use std::process::Command;
use super::{AGENT_FILE, AGENT_DIR, SERVICE_NAME, CRONTAB_FILE, CRONTAB_LINE, read_agent_pid, restart_cron, run_cmd};
use super::cgroup;

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

/// Spawn hades-agent under cgroup resource limits (v1, v2, or hybrid — auto-detected).
pub fn sysvinit_start() -> Result<()> {
    if read_agent_pid().is_ok() {
        return Ok(()); // already running — idempotent
    }

    // Auto-detect v1/v2/hybrid and apply cpu+memory limits.
    // Failure is non-fatal: agent runs without resource constraints.
    let cg = cgroup::setup(SERVICE_NAME)
        .map_err(|e| eprintln!("warning: cgroup setup failed (running without limits): {e}"))
        .ok();

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

    if let Some(cg) = cg {
        if let Err(e) = cg.add_proc(pid) {
            eprintln!("warning: failed to add pid {pid} to cgroup: {e}");
        }
    }
    Ok(())
}
