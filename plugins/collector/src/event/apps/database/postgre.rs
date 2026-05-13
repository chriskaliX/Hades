use crate::event::apps::{execute, find_version, AppProc, IApp};
use std::collections::HashMap;

pub struct PostgreSql {
    version: String,
}

impl PostgreSql {
    pub fn new() -> Self { PostgreSql { version: String::new() } }
}

impl IApp for PostgreSql {
    fn name(&self)     -> &'static str { "postgresql" }
    fn app_type(&self) -> &'static str { "database" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool {
        p.name == "postgres" && p.argv.contains("config_file")
    }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["-V"])?;
        // "postgres (PostgreSQL) 14.5"
        self.version = find_version(&out);
        if self.version.is_empty() {
            return Err(anyhow::anyhow!("version not found"));
        }
        Ok(HashMap::new())
    }
}
