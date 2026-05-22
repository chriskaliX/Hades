use anyhow::{bail, Result};
use super::{SERVICE_NAME, collect_proc_tree, read_agent_pid, run_cmd};

pub fn run() -> Result<()> {
    match crate::config::get("service_type").as_str() {
        "systemd" => run_cmd("systemctl", ["status", SERVICE_NAME]),
        "sysvinit" => sysvinit_status(),
        t          => bail!("unknown service_type: '{t}'"),
    }
}

fn sysvinit_status() -> Result<()> {
    match read_agent_pid() {
        Err(_) => {
            println!("hades-agent is dead");
        }
        Ok(pid) => {
            println!("hades-agent is running (pid {pid})");
            let pids = collect_proc_tree(pid);
            if pids.len() > 1 {
                println!("process tree:");
                for p in &pids {
                    println!("  {p}");
                }
            }
        }
    }
    Ok(())
}
