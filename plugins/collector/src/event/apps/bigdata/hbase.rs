use crate::event::apps::{find_version, jar_names_for_pid, AppProc, IApp};
use std::collections::HashMap;

pub struct Hbase {
    version: String,
}

impl Hbase {
    pub fn new() -> Self { Hbase { version: String::new() } }
}

impl IApp for Hbase {
    fn name(&self)     -> &'static str { "hbase" }
    fn app_type(&self) -> &'static str { "bigdata" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool {
        p.name == "java" && p.argv.contains("org.apache.hadoop.hbase.master")
    }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        self.version.clear();
        // "hbase-server-2.4.13.jar"
        for jar in jar_names_for_pid(p.pid) {
            if jar.starts_with("hbase-server-") && jar.ends_with(".jar") {
                let mid = jar.trim_start_matches("hbase-server-").trim_end_matches(".jar");
                let ver = find_version(mid);
                if !ver.is_empty() { self.version = ver; break; }
            }
        }
        Ok(HashMap::new())
    }
}
