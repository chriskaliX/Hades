use crate::event::apps::{find_version, jar_names_for_pid, AppProc, IApp};
use std::collections::HashMap;

pub struct Activemq {
    version: String,
}

impl Activemq {
    pub fn new() -> Self { Activemq { version: String::new() } }
}

impl IApp for Activemq {
    fn name(&self)     -> &'static str { "activemq" }
    fn app_type(&self) -> &'static str { "bigdata" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool {
        if p.name != "java" { return false; }
        // Version is extracted from jar: "activemq-client-5.17.1.jar"
        self.version.clear();
        for jar in jar_names_for_pid(p.pid) {
            if jar.starts_with("activemq-client-") && jar.ends_with(".jar") {
                let mid = jar.trim_start_matches("activemq-client-").trim_end_matches(".jar");
                let ver = find_version(mid);
                if !ver.is_empty() {
                    self.version = ver;
                    return true;
                }
            }
        }
        false
    }

    fn run(&mut self, _p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        // Version already populated during matches()
        Ok(HashMap::new())
    }
}
