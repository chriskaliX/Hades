/// SystemdUnit collector — data_type 3011.
/// Queries systemd via D-Bus (ListUnits).  Falls back to `systemctl` subprocess.
/// Mirrors Go's event/systems/systemd_unit.go.
use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;

use crate::manager::{EventMode, IEvent};
use crate::event::{hash, make_record};

const DATA_TYPE: i32 = 3011;

pub struct SystemdUnit;

#[async_trait]
impl IEvent for SystemdUnit {
    fn name(&self)        -> &'static str { "systemd_unit" }
    fn data_type(&self)   -> i32          { DATA_TYPE }
    fn flag(&self)        -> EventMode    { EventMode::Periodic }
    fn immediately(&self) -> bool         { false }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        let units = tokio::task::spawn_blocking(list_units).await??;
        let seq   = hash();
        for u in units {
            let mut fields = u;
            fields.insert("package_seq".into(), seq.clone());
            let _ = client.send_record(&make_record(DATA_TYPE, fields));
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok(())
    }
}

/// Call `systemctl list-units --all --plain --no-legend` and parse output.
/// Only service units are returned — mirrors Go's `isService()` filter.
fn list_units() -> Result<Vec<HashMap<String, String>>> {
    let out = Command::new("systemctl")
        .args(["list-units", "--all", "--plain", "--no-legend", "--no-pager"])
        .output()?;
    if !out.status.success() { return Ok(Vec::new()); }

    let mut result = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // "UNIT  LOAD  ACTIVE  SUB  DESCRIPTION"
        // Columns can be separated by multiple spaces; split by whitespace then
        // rejoin description (5th token onwards).
        let cols: Vec<&str> = line.splitn(6, char::is_whitespace)
            .filter(|s| !s.is_empty())
            .collect();
        if cols.len() < 4 { continue; }
        // Only .service units (mirrors Go's isService check)
        if !cols[0].ends_with(".service") { continue; }

        let mut m = HashMap::new();
        m.insert("name".into(),         cols[0].to_owned());
        m.insert("load_state".into(),   cols.get(1).unwrap_or(&"").to_string());
        m.insert("active_state".into(), cols.get(2).unwrap_or(&"").to_string());
        m.insert("sub_state".into(),    cols.get(3).unwrap_or(&"").to_string());
        m.insert("description".into(),  cols.get(4).unwrap_or(&"").to_string());
        result.push(m);
    }
    Ok(result)
}
