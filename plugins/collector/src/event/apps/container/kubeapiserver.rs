use crate::event::apps::{execute, find_version, AppProc, IApp};
use std::collections::HashMap;

pub struct KubeApiserver {
    version: String,
}

impl KubeApiserver {
    pub fn new() -> Self { KubeApiserver { version: String::new() } }
}

impl IApp for KubeApiserver {
    fn name(&self)     -> &'static str { "kube-apiserver" }
    fn app_type(&self) -> &'static str { "container" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "kube-apiserver" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["--version"])?;
        // "Kubernetes v1.25.2"
        if let Some(rest) = out.strip_prefix("Kubernetes ") {
            self.version = rest.trim_start_matches('v').split_whitespace()
                              .next().unwrap_or("").to_owned();
        } else {
            self.version = find_version(&out);
        }
        if self.version.is_empty() {
            return Err(anyhow::anyhow!("version not found"));
        }
        Ok(HashMap::new())
    }
}
