//! Reads and writes `/etc/hades/specified_env` — a simple `KEY=VALUE` properties
//! file consumed by hades-agent at startup via `EnvironmentFile=` in the systemd
//! unit and passed explicitly to the child process in sysvinit mode.

use std::collections::HashMap;
use std::fs;

pub const CFG_FILE: &str = "/etc/hades/specified_env";

/// Load all key-value pairs from the config file.
/// Returns an empty map if the file does not exist.
pub fn read() -> HashMap<String, String> {
    let content = fs::read_to_string(CFG_FILE).unwrap_or_default();
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_owned(), v.trim().to_owned());
        }
    }
    map
}

/// Retrieve a single value (empty string if absent).
pub fn get(key: &str) -> String {
    read().get(key).cloned().unwrap_or_default()
}

/// Insert or update a single key and persist the file.
pub fn set(key: &str, value: &str) -> anyhow::Result<()> {
    let mut map = read();
    map.insert(key.to_owned(), value.to_owned());
    write_all(&map)
}

fn write_all(map: &HashMap<String, String>) -> anyhow::Result<()> {
    let content: String = map
        .iter()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect();
    fs::write(CFG_FILE, content)?;
    Ok(())
}
