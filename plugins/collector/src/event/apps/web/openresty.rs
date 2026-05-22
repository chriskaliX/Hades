use crate::event::apps::{execute, AppProc, IApp};
use std::collections::HashMap;

pub struct Openresty {
    version: String,
}

impl Openresty {
    pub fn new() -> Self { Openresty { version: String::new() } }
}

impl IApp for Openresty {
    fn name(&self)     -> &'static str { "openresty" }
    fn app_type(&self) -> &'static str { "web" }
    fn version(&self)  -> &str         { &self.version }

    fn matches(&mut self, p: &AppProc) -> bool { p.name == "openresty" }

    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        let out = execute(p, &["-v"])?;
        // Output may be on stdout or stderr, may be prefixed:
        //   "openresty/1.21.4.1"  or  "openresty version openresty/1.21.4.1"
        if let Some(pos) = out.find("openresty/") {
            let rest = &out[pos + "openresty/".len()..];
            self.version = rest.split(|c: char| c.is_whitespace()).next().unwrap_or("").to_owned();
        }
        if self.version.is_empty() {
            return Err(anyhow::anyhow!("version not found"));
        }
        Ok(HashMap::new())
    }
}
