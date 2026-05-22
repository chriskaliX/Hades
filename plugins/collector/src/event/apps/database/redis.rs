use crate::event::apps::{execute_with_name, AppProc, IApp};
use std::collections::HashMap;
use std::path::Path;

pub struct Redis {
    version: String,
}

impl Redis {
    pub fn new() -> Self { Redis { version: String::new() } }
}

impl IApp for Redis {
    fn name(&self)     -> &'static str { "redis" }
    fn app_type(&self) -> &'static str { "database" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "redis-server" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        // exe may be redis-check-rdb (symlink); always call redis-server -v
        let dir = Path::new(&p.exe).parent()
                      .map(|d| d.to_string_lossy().into_owned())
                      .unwrap_or_default();
        let bin = format!("{}/redis-server", dir);
        let out = execute_with_name(p, &bin, &["-v"])?;
        // "Redis server v=7.0.1 sha=… …"
        for word in out.split_whitespace() {
            if let Some(v) = word.strip_prefix("v=") {
                self.version = v.trim().to_owned();
                return Ok(HashMap::new());
            }
        }
        Err(anyhow::anyhow!("version not found"))
    }
}
