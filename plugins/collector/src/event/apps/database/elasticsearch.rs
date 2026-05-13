use crate::event::apps::{find_version, jar_names_for_pid, AppProc, IApp};
use std::collections::HashMap;

pub struct ElasticSearch {
    version: String,
}

impl ElasticSearch {
    pub fn new() -> Self { ElasticSearch { version: String::new() } }
}

impl IApp for ElasticSearch {
    fn name(&self)     -> &'static str { "elasticsearch" }
    fn app_type(&self) -> &'static str { "database" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool {
        p.name == "java"
            && p.argv.contains("org.elasticsearch.bootstrap.Elasticsearch")
    }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        self.version.clear();
        // "elasticsearch-8.4.0.jar"
        for jar in jar_names_for_pid(p.pid) {
            if jar.starts_with("elasticsearch-") && jar.ends_with(".jar") {
                let mid = jar.trim_start_matches("elasticsearch-").trim_end_matches(".jar");
                let ver = find_version(mid);
                if !ver.is_empty() { self.version = ver; break; }
            }
        }
        Ok(HashMap::new())
    }
}
