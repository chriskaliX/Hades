use anyhow::Result;
use std::fs;
use super::{CRONTAB_FILE, CRONTAB_LINE, restart_cron};

/// Called by cron every minute in sysvinit mode.
/// If the agent is dead, start it and re-register the crontab.
pub fn run() -> Result<()> {
    if crate::config::get("service_type") != "sysvinit" {
        return Ok(());
    }
    if super::read_agent_pid().is_err() {
        // Agent is dead — restart it
        super::start::sysvinit_start()?;
        fs::write(CRONTAB_FILE, CRONTAB_LINE)?;
        restart_cron();
    }
    Ok(())
}
