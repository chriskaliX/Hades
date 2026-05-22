use crate::event::apps::{find_version, jar_names_for_pid, AppProc, IApp};
use std::collections::HashMap;

pub struct Flink {
    version: String,
}

impl Flink {
    pub fn new() -> Self { Flink { version: String::new() } }
}

impl IApp for Flink {
    fn name(&self)     -> &'static str { "flink" }
    fn app_type(&self) -> &'static str { "bigdata" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool {
        p.name == "java" && p.argv.contains("org.apache.flink.")
    }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        self.version.clear();
        // "flink-dist-1.15.2.jar"
        for jar in jar_names_for_pid(p.pid) {
            if jar.starts_with("flink-dist-") && jar.ends_with(".jar") {
                let mid = jar.trim_start_matches("flink-dist-").trim_end_matches(".jar");
                let ver = find_version(mid);
                if !ver.is_empty() { self.version = ver; break; }
            }
        }
        let mut m = HashMap::new();
        let run_mode = if p.argv.contains("jobmanager.") {
            "jobmanager"
        } else if p.argv.contains("taskmanager.") {
            "taskmanager"
        } else {
            "unknown"
        };
        m.insert("run_mode".into(), run_mode.into());
        Ok(m)
    }
}
