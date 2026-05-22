use crate::event::apps::{execute, find_version, AppProc, IApp};
use std::collections::HashMap;

pub struct Etcd {
    version: String,
}

impl Etcd {
    pub fn new() -> Self { Etcd { version: String::new() } }
}

impl IApp for Etcd {
    fn name(&self)     -> &'static str { "etcd" }
    fn app_type(&self) -> &'static str { "database" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "etcd" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["--version"])?;
        // "etcd Version: 3.5.5"
        for line in out.lines() {
            if let Some(rest) = line.strip_prefix("etcd Version:") {
                self.version = rest.trim().to_owned();
                return Ok(HashMap::new());
            }
        }
        self.version = find_version(&out);
        if self.version.is_empty() {
            return Err(anyhow::anyhow!("version not found"));
        }
        Ok(HashMap::new())
    }
}
