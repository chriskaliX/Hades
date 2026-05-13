use crate::event::apps::{execute, AppProc, IApp};
use std::collections::HashMap;

pub struct Memcache {
    version: String,
}

impl Memcache {
    pub fn new() -> Self { Memcache { version: String::new() } }
}

impl IApp for Memcache {
    fn name(&self)     -> &'static str { "memcache" }
    fn app_type(&self) -> &'static str { "database" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "memcached" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["--version"])?;
        // "memcached 1.6.17"
        self.version = out.trim_start_matches("memcached ").trim().to_owned();
        Ok(HashMap::new())
    }
}
