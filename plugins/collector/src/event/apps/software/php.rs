use crate::event::apps::{execute, find_version, AppProc, IApp};
use std::collections::HashMap;

pub struct Php {
    version: String,
}

impl Php {
    pub fn new() -> Self { Php { version: String::new() } }
}

impl IApp for Php {
    fn name(&self)     -> &'static str { "php" }
    fn app_type(&self) -> &'static str { "software" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "php-fpm" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["-v"])?;
        // "PHP 8.1.13 (fpm-fcgi) …"
        self.version = find_version(&out);
        if self.version.is_empty() {
            return Err(anyhow::anyhow!("version not found"));
        }
        Ok(HashMap::new())
    }
}
