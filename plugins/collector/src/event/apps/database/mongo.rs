use crate::event::apps::{execute, AppProc, IApp};
use std::collections::HashMap;

pub struct MongoDB {
    version: String,
}

impl MongoDB {
    pub fn new() -> Self { MongoDB { version: String::new() } }
}

impl IApp for MongoDB {
    fn name(&self)     -> &'static str { "mongo" }
    fn app_type(&self) -> &'static str { "database" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "mongod" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["--version"])?;
        // "db version v6.0.1"
        self.version = out.lines().next()
            .map(|l| l.trim_start_matches("db version v").trim().to_owned())
            .unwrap_or_default();
        Ok(HashMap::new())
    }
}
