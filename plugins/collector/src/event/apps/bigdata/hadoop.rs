use crate::event::apps::{execute_with_name, find_version, AppProc, IApp};
use std::collections::HashMap;

pub struct Hadoop {
    version: String,
}

impl Hadoop {
    pub fn new() -> Self { Hadoop { version: String::new() } }
}

impl IApp for Hadoop {
    fn name(&self)     -> &'static str { "hadoop" }
    fn app_type(&self) -> &'static str { "bigdata" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool {
        p.name == "java"
            && p.argv.contains("org.apache.hadoop.")
            && p.argv.contains("DataNode")
    }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let root = p.argv.split_whitespace()
            .find(|s| s.starts_with("hadoop.home.dir="))
            .map(|s| s.trim_start_matches("hadoop.home.dir="))
            .unwrap_or("/usr/local/hadoop");
        let bin = format!("{}/bin/hadoop", root);
        if let Ok(out) = execute_with_name(p, &bin, &["version"]) {
            // "Hadoop 3.3.4"
            for line in out.lines() {
                if line.starts_with("Hadoop ") {
                    self.version = line.trim_start_matches("Hadoop ").trim().to_owned();
                    break;
                }
            }
            if self.version.is_empty() { self.version = find_version(&out); }
        }
        Ok(HashMap::new())
    }
}
