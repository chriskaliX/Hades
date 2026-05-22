use crate::event::apps::{find_version, jar_names_for_pid, AppProc, IApp};
use std::collections::HashMap;

pub struct Kafka {
    version: String,
}

impl Kafka {
    pub fn new() -> Self { Kafka { version: String::new() } }
}

impl IApp for Kafka {
    fn name(&self)     -> &'static str { "kafka" }
    fn app_type(&self) -> &'static str { "bigdata" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool {
        p.name == "java" && p.argv.contains("kafka.Kafka")
    }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        self.version.clear();
        // Version from jar: "kafka_2.13-3.3.1.jar" → take the part after "-"
        for jar in jar_names_for_pid(p.pid) {
            if jar.starts_with("kafka_") && jar.ends_with(".jar") {
                let mid = jar.trim_start_matches("kafka_").trim_end_matches(".jar");
                if let Some(v) = mid.split_once('-').map(|x| x.1) {
                    let ver = find_version(v);
                    if !ver.is_empty() {
                        self.version = ver;
                        break;
                    }
                }
            }
        }
        Ok(HashMap::new())
    }
}
