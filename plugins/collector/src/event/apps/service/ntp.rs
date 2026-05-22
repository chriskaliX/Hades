use crate::event::apps::{execute, find_version, AppProc, IApp};
use std::collections::HashMap;

pub struct Ntp {
    version: String,
}

impl Ntp {
    pub fn new() -> Self { Ntp { version: String::new() } }
}

impl IApp for Ntp {
    fn name(&self)     -> &'static str { "ntp" }
    fn app_type(&self) -> &'static str { "service" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "ntpd" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["--version"])?;
        // "ntpd 4.2.8p15@1.3728-o …"
        self.version = find_version(&out);
        Ok(HashMap::new())
    }
}
