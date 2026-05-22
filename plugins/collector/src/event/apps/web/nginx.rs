use crate::event::apps::{execute, find_version, AppProc, IApp, ERR_IGNORE};
use std::collections::HashMap;

pub struct Nginx {
    version: String,
}

impl Nginx {
    pub fn new() -> Self { Nginx { version: String::new() } }
}

impl IApp for Nginx {
    fn name(&self)     -> &'static str { "nginx" }
    fn app_type(&self) -> &'static str { "web" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool {
        p.name == "nginx" && p.argv.contains("master")
    }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["-v"])?;
        // Ignore if the binary is actually Tengine
        if out.contains("Tengine/") {
            return Err(anyhow::anyhow!(ERR_IGNORE));
        }
        self.version = find_version(&out);
        if self.version.is_empty() {
            return Err(anyhow::anyhow!("version not found"));
        }
        let mut m = HashMap::new();
        m.insert(
            "process_type".into(),
            if p.argv.contains("master process") { "master" } else { "worker" }.into(),
        );
        Ok(m)
    }
}
