use crate::event::apps::{execute, find_version, AppProc, IApp};
use std::collections::HashMap;

pub struct Containerd {
    version: String,
}

impl Containerd {
    pub fn new() -> Self { Containerd { version: String::new() } }
}

impl IApp for Containerd {
    fn name(&self)     -> &'static str { "containerd" }
    fn app_type(&self) -> &'static str { "container" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "containerd" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["--version"])?;
        // "containerd github.com/containerd/containerd v1.6.8 …"
        self.version = find_version(&out);
        if self.version.is_empty() {
            return Err(anyhow::anyhow!("version not found"));
        }
        Ok(HashMap::new())
    }
}
