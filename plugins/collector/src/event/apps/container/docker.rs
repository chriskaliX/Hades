use crate::event::apps::{execute, AppProc, IApp};
use std::collections::HashMap;

pub struct Docker {
    version: String,
}

impl Docker {
    pub fn new() -> Self { Docker { version: String::new() } }
}

impl IApp for Docker {
    fn name(&self)     -> &'static str { "docker" }
    fn app_type(&self) -> &'static str { "container" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "dockerd" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["--version"])?;
        // "Docker version 20.10.18, build …"
        if let Some(rest) = out.strip_prefix("Docker version ") {
            self.version = rest.split([',', ' ']).next().unwrap_or("").to_owned();
        }
        if self.version.is_empty() {
            return Err(anyhow::anyhow!("version not found"));
        }
        Ok(HashMap::new())
    }
}
