use crate::event::apps::{execute, AppProc, IApp};
use std::collections::HashMap;

pub struct Tengine {
    version: String,
}

impl Tengine {
    pub fn new() -> Self { Tengine { version: String::new() } }
}

impl IApp for Tengine {
    fn name(&self)     -> &'static str { "tengine" }
    fn app_type(&self) -> &'static str { "web" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "tengine" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["-v"])?;
        // "Tengine/2.3.3"
        if let Some(v) = out.split_whitespace().find(|s| s.starts_with("Tengine/")) {
            self.version = v.trim_start_matches("Tengine/").to_owned();
        }
        Ok(HashMap::new())
    }
}
