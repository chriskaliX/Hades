use crate::event::apps::{execute, find_version, AppProc, IApp};
use std::collections::HashMap;

pub struct Kubelet {
    version: String,
}

impl Kubelet {
    pub fn new() -> Self { Kubelet { version: String::new() } }
}

impl IApp for Kubelet {
    fn name(&self)     -> &'static str { "kubelet" }
    fn app_type(&self) -> &'static str { "container" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "kubelet" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["--version"])?;
        // "Kubernetes v1.25.2"
        if let Some(v) = out.split_whitespace().find(|s| s.starts_with('v')) {
            self.version = v.trim_start_matches('v').to_owned();
        } else {
            self.version = find_version(&out);
        }
        if self.version.is_empty() {
            return Err(anyhow::anyhow!("version not found"));
        }
        Ok(HashMap::new())
    }
}
