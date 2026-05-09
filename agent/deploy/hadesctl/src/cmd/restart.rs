use anyhow::{bail, Result};
use std::fs;
use super::{SERVICE_NAME, CRONTAB_FILE, CRONTAB_LINE, restart_cron, run_cmd};

pub fn run() -> Result<()> {
    match crate::config::get("service_type").as_str() {
        "systemd"  => run_cmd("systemctl", ["restart", SERVICE_NAME]),
        "sysvinit" => sysvinit_restart(),
        t          => bail!("unknown service_type: '{t}'"),
    }
}

fn sysvinit_restart() -> Result<()> {
    // Remove watchdog before stop; reinstall after successful start
    let _ = fs::remove_file(CRONTAB_FILE);
    restart_cron();

    super::stop::sysvinit_stop()?;
    super::start::sysvinit_start()?;

    fs::write(CRONTAB_FILE, CRONTAB_LINE)?;
    restart_cron();
    Ok(())
}
