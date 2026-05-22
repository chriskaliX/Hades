use crate::event::apps::{execute, find_version, AppProc, IApp};
use std::collections::HashMap;

pub struct Apache2 {
    version: String,
}

impl Apache2 {
    pub fn new() -> Self { Apache2 { version: String::new() } }
}

impl IApp for Apache2 {
    fn name(&self)     -> &'static str { "apache2" }
    fn app_type(&self) -> &'static str { "web" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "apache2" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["-v"])?;
        // "Server version: Apache/2.4.54 (Debian)"
        self.version = find_version(&out);
        if self.version.is_empty() {
            return Err(anyhow::anyhow!("version not found"));
        }
        Ok(HashMap::new())
    }
}
