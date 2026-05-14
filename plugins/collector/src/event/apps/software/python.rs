use crate::event::apps::{AppProc, IApp};
use std::collections::HashMap;

pub struct Python {
    version: String,
}

impl Python {
    pub fn new() -> Self { Python { version: String::new() } }
}

impl IApp for Python {
    fn name(&self)     -> &'static str { "python" }
    fn app_type(&self) -> &'static str { "software" }
    fn version(&self)  -> &str         { &self.version }

    /// Matches "python3", "python3.9", "python2.7", etc.
    /// Mirrors Go regex `^python\d(\.\d+)?$`.
    fn matches(&mut self, p: &AppProc) -> bool {
        let n = &p.name;
        if !n.starts_with("python") { return false; }
        let rest = &n["python".len()..];
        if rest.is_empty() { return false; }
        let mut chars = rest.chars();
        // First char must be a digit
        if !chars.next().is_some_and(|c| c.is_ascii_digit()) { return false; }
        // Optionally: "." followed by more digits
        let tail: String = chars.collect();
        if tail.is_empty() {
            self.version = rest.to_owned();
            return true;
        }
        if !tail.starts_with('.') { return false; }
        if tail[1..].chars().all(|c| c.is_ascii_digit()) {
            self.version = rest.to_owned();
            return true;
        }
        false
    }

    fn run(&mut self, _p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        // Version derived from process name in matches(); nothing extra to collect.
        Ok(HashMap::new())
    }
}
