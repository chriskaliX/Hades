use crate::event::apps::{execute, find_version, AppProc, IApp};
use std::collections::HashMap;

pub struct Nscd {
    version: String,
}

impl Nscd {
    pub fn new() -> Self { Nscd { version: String::new() } }
}

impl IApp for Nscd {
    fn name(&self)     -> &'static str { "nscd" }
    fn app_type(&self) -> &'static str { "service" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "nscd" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["--version"])?;
        // "nscd (GNU C Library) 2.35 …"
        self.version = find_version(&out);
        Ok(HashMap::new())
    }
}
