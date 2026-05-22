use crate::event::apps::{find_version, jar_names_for_pid, AppProc, IApp};
use std::collections::HashMap;

pub struct Storm {
    version: String,
}

impl Storm {
    pub fn new() -> Self { Storm { version: String::new() } }
}

impl IApp for Storm {
    fn name(&self)     -> &'static str { "storm" }
    fn app_type(&self) -> &'static str { "bigdata" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool {
        p.name == "java" && p.argv.contains("org.apache.storm.daemon.")
    }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        self.version.clear();
        // "storm-client-2.4.0.jar"
        for jar in jar_names_for_pid(p.pid) {
            if jar.starts_with("storm-client-") && jar.ends_with(".jar") {
                let mid = jar.trim_start_matches("storm-client-").trim_end_matches(".jar");
                let ver = find_version(mid);
                if !ver.is_empty() { self.version = ver; break; }
            }
        }
        Ok(HashMap::new())
    }
}
