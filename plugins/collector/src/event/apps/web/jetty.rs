use crate::event::apps::{find_version, jar_names_for_pid, AppProc, IApp};
use std::collections::HashMap;

pub struct Jetty {
    version: String,
}

impl Jetty {
    pub fn new() -> Self { Jetty { version: String::new() } }
}

impl IApp for Jetty {
    fn name(&self)     -> &'static str { "jetty" }
    fn app_type(&self) -> &'static str { "web" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool {
        p.name == "java" && p.argv.contains("jetty")
    }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        self.version.clear();
        // "jetty-client-9.4.48.v20220622.jar"
        for jar in jar_names_for_pid(p.pid) {
            if jar.starts_with("jetty-client-") && jar.ends_with(".jar") {
                let mid = jar.trim_start_matches("jetty-client-").trim_end_matches(".jar");
                let ver = find_version(mid);
                if !ver.is_empty() { self.version = ver; break; }
            }
        }
        if self.version.is_empty() {
            return Err(anyhow::anyhow!("version not found"));
        }
        Ok(HashMap::new())
    }
}
