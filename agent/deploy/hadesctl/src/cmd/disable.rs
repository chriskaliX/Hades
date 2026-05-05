use anyhow::{bail, Result};
use super::{SERVICE_NAME, has_cmd, run_cmd};

pub fn run() -> Result<()> {
    match crate::config::get("service_type").as_str() {
        "systemd" => {
            run_cmd("systemctl", ["disable", SERVICE_NAME])
        }
        "sysvinit" => {
            if has_cmd("update-rc.d") {
                run_cmd("update-rc.d", ["-f", SERVICE_NAME, "remove"])
            } else if has_cmd("chkconfig") {
                run_cmd("chkconfig", ["--del", SERVICE_NAME])
            } else {
                bail!("no available service management tool (update-rc.d or chkconfig)");
            }
        }
        t => bail!("unknown service_type: '{t}'"),
    }
}
