use crate::event::apps::{execute, find_version, AppProc, IApp};
use std::collections::HashMap;

pub struct Mysql {
    version: String,
}

impl Mysql {
    pub fn new() -> Self { Mysql { version: String::new() } }
}

impl IApp for Mysql {
    fn name(&self)     -> &'static str { "mysql" }
    fn app_type(&self) -> &'static str { "database" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "mysqld" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["-V"])?;
        // "mysqld  Ver 8.0.30 Distrib 8.0.30 …"
        if let Some(ver_part) = out.split("Ver ").nth(1) {
            self.version = find_version(ver_part);
        }
        if self.version.is_empty() { self.version = find_version(&out); }
        if self.version.is_empty() {
            return Err(anyhow::anyhow!("version not found"));
        }
        Ok(HashMap::new())
    }
}
