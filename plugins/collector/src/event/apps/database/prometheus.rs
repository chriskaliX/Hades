use crate::event::apps::{execute, AppProc, IApp};
use std::collections::HashMap;

pub struct Prometheus {
    version: String,
}

impl Prometheus {
    pub fn new() -> Self { Prometheus { version: String::new() } }
}

impl IApp for Prometheus {
    fn name(&self)     -> &'static str { "prometheus" }
    fn app_type(&self) -> &'static str { "database" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "prometheus" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["--version"])?;
        // "prometheus, version 2.38.0 (branch: …)"
        for line in out.lines() {
            if let Some(rest) = line.strip_prefix("prometheus, version ") {
                self.version = rest.split_whitespace().next().unwrap_or("").to_owned();
                return Ok(HashMap::new());
            }
        }
        Err(anyhow::anyhow!("version not found"))
    }
}
