/// Iptables collector — data_type 3013.
/// Reads tables via `iptables -L -n -v` / `ip6tables`.
/// Mirrors Go's event/networks/iptables.go field layout.
use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;

use crate::manager::{EventMode, IEvent};
use crate::event::{hash, make_record};

const DATA_TYPE: i32 = 3013;

static TABLES: &[&str] = &["filter", "nat", "mangle", "raw"];

pub struct Iptables;

#[async_trait]
impl IEvent for Iptables {
    fn name(&self)        -> &'static str { "iptables" }
    fn data_type(&self)   -> i32          { DATA_TYPE }
    fn flag(&self)        -> EventMode    { EventMode::Periodic }
    fn immediately(&self) -> bool         { false }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        let records = tokio::task::spawn_blocking(collect_iptables).await?;
        let seq     = hash();
        for mut fields in records {
            fields.insert("package_seq".into(), seq.clone());
            let _ = client.send_record(&make_record(DATA_TYPE, fields));
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok(())
    }
}

/// Returns one record per rule across ipv4 + ipv6.
fn collect_iptables() -> Vec<HashMap<String, String>> {
    let mut result = Vec::new();
    for (bin, _family) in [("iptables", "4"), ("ip6tables", "6")] {
        for table in TABLES {
            // -L <chain> -n -v --line-numbers for each chain in the table
            let out = match Command::new(bin)
                .args(["-t", table, "-L", "-n", "-v", "--line-numbers", "-x"])
                .output() {
                Ok(o) if o.status.success() => o,
                _ => continue,
            };
            let text = String::from_utf8_lossy(&out.stdout);
            let mut chain = String::new();
            for line in text.lines() {
                let t = line.trim();
                if t.starts_with("Chain ") {
                    // "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)"
                    chain = t.split_whitespace().nth(1).unwrap_or("").to_owned();
                    continue;
                }
                // Header lines
                if t.starts_with("num") || t.starts_with("pkts") || t.is_empty() { continue; }
                // Data line: num pkts bytes target prot opt in out source destination [options]
                let cols: Vec<&str> = t.split_whitespace().collect();
                if cols.len() < 10 { continue; }
                let mut m: HashMap<String, String> = HashMap::new();
                m.insert("table".into(),       table.to_string());
                m.insert("chain".into(),       chain.clone());
                m.insert("pkt".into(),         cols[1].to_owned());
                m.insert("bytes".into(),       cols[2].to_owned());
                m.insert("target".into(),      cols[3].to_owned());
                m.insert("prot".into(),        cols[4].to_owned());
                m.insert("opt".into(),         cols[5].to_owned());
                m.insert("in".into(),          cols[6].to_owned());
                m.insert("out".into(),         cols[7].to_owned());
                m.insert("source".into(),      cols[8].to_owned());
                m.insert("destination".into(), cols[9].to_owned());
                m.insert("options".into(),     cols.get(10..).map(|s| s.join(" ")).unwrap_or_default());
                m.insert("rule".into(),        t.to_owned());
                result.push(m);
            }
        }
    }
    result
}
