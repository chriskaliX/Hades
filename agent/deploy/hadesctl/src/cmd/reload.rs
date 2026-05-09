use anyhow::{bail, Result};
use super::restart_cron;

pub fn run() -> Result<()> {
    match crate::config::get("service_type").as_str() {
        "systemd" => {
            // systemctl daemon-reload reloads unit files; ignore the watchdog
            // timer side-effect (see https://github.com/systemd/systemd/issues/9467)
            let _ = std::process::Command::new("systemctl")
                .arg("daemon-reload")
                .status();
            Ok(())
        }
        "sysvinit" => {
            restart_cron();
            Ok(())
        }
        t => bail!("unknown service_type: '{t}'"),
    }
}
