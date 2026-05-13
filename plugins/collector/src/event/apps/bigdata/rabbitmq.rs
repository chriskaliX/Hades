use crate::event::apps::{execute_with_name, AppProc, IApp};
use std::collections::HashMap;
use std::path::Path;

pub struct Rabbitmq {
    version: String,
}

impl Rabbitmq {
    pub fn new() -> Self { Rabbitmq { version: String::new() } }
}

impl IApp for Rabbitmq {
    fn name(&self)     -> &'static str { "rabbitmq" }
    fn app_type(&self) -> &'static str { "bigdata" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "beam.smp" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        self.version.clear();
        let bin = if p.argv.contains("rabbitmq-server") {
            find_rabbitmqctl_in_fds(p.pid).unwrap_or_else(|| "rabbitmqctl".to_owned())
        } else {
            "rabbitmqctl".to_owned()
        };
        if let Ok(out) = execute_with_name(p, &bin, &["version"]) {
            self.version = out.trim().to_owned();
        }
        Ok(HashMap::new())
    }
}

/// Locate `rabbitmqctl` by finding `rabbitmq-server` in the process's fd links.
fn find_rabbitmqctl_in_fds(pid: i32) -> Option<String> {
    let fd_dir = format!("/proc/{}/fd", pid);
    if let Ok(entries) = std::fs::read_dir(&fd_dir) {
        for entry in entries.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                let p = Path::new(&target);
                if p.file_name().map_or(false, |n| n == "rabbitmq-server") {
                    if let Some(dir) = p.parent() {
                        return Some(dir.join("rabbitmqctl").to_string_lossy().into_owned());
                    }
                }
            }
        }
    }
    None
}
