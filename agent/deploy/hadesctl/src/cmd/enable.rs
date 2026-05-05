use anyhow::{bail, Result};
use super::{SERVICE_FILE, SERVICE_NAME, has_cmd, run_cmd};

pub fn run() -> Result<()> {
    match crate::config::get("service_type").as_str() {
        "systemd" => {
            run_cmd("systemctl", ["enable", SERVICE_FILE])
        }
        "sysvinit" => {
            if has_cmd("update-rc.d") {
                run_cmd("update-rc.d", [SERVICE_NAME, "defaults"])
            } else if has_cmd("chkconfig") {
                run_cmd("chkconfig", ["--add", SERVICE_NAME])
            } else {
                bail!("no available service management tool (update-rc.d or chkconfig)");
            }
        }
        t => bail!("unknown service_type: '{t}'"),
    }
}
