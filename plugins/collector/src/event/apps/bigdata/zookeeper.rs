use crate::event::apps::{find_version, jar_names_for_pid, AppProc, IApp};
use std::collections::HashMap;

pub struct Zookeeper {
    version: String,
}

impl Zookeeper {
    pub fn new() -> Self { Zookeeper { version: String::new() } }
}

impl IApp for Zookeeper {
    fn name(&self)     -> &'static str { "zookeeper" }
    fn app_type(&self) -> &'static str { "bigdata" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool {
        p.name == "java" && p.argv.contains("org.apache.zookeeper.")
    }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        self.version.clear();
        // "zookeeper-3.8.0.jar"
        for jar in jar_names_for_pid(p.pid) {
            if jar.starts_with("zookeeper-") && jar.ends_with(".jar") {
                let mid = jar.trim_start_matches("zookeeper-").trim_end_matches(".jar");
                let ver = find_version(mid);
                if !ver.is_empty() { self.version = ver; break; }
            }
        }
        Ok(HashMap::new())
    }
}
