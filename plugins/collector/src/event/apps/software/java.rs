use crate::event::apps::{execute, find_version, AppProc, IApp};
use std::collections::HashMap;

pub struct Java {
    version: String,
}

impl Java {
    pub fn new() -> Self { Java { version: String::new() } }
}

impl IApp for Java {
    fn name(&self)     -> &'static str { "java" }
    fn app_type(&self) -> &'static str { "software" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "java" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["-version"])?;
        // First line: 'openjdk version "11.0.16" 2022-07-19'
        let mut m = HashMap::new();
        let first = out.lines().next().unwrap_or("").trim();
        m.insert("version_detail".into(), first.to_owned());
        // Extract version between first pair of double-quotes
        if let (Some(s), Some(e)) = (first.find('"'), first.rfind('"')) {
            if s < e { self.version = first[s + 1..e].to_owned(); }
        }
        if self.version.is_empty() { self.version = find_version(&out); }
        Ok(m)
    }
}
