/// Kmod collector — data_type 3009.
/// Reads /proc/modules.  Mirrors Go's event/systems/kmod.go.
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;

use crate::manager::{EventMode, IEvent};
use crate::event::{hash, make_record};

const DATA_TYPE: i32 = 3009;

pub struct Kmod;

#[async_trait]
impl IEvent for Kmod {
    fn name(&self)      -> &'static str { "kmod" }
    fn data_type(&self) -> i32          { DATA_TYPE }
    fn flag(&self)      -> EventMode    { EventMode::Periodic }
    fn immediately(&self) -> bool       { false }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        let seq = hash();
        let f = match File::open("/proc/modules") { Ok(f) => f, Err(_) => return Ok(()) };
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() <= 5 { continue; }
            let mut fields = HashMap::new();
            fields.insert("name".into(),     cols[0].to_owned());
            fields.insert("size".into(),     cols[1].to_owned());
            fields.insert("refcount".into(), cols[2].to_owned());
            fields.insert("used_by".into(),  cols[3].trim_end_matches(',').to_owned());
            fields.insert("state".into(),    cols[4].to_owned());
            fields.insert("addr".into(),     cols[5].to_owned());
            fields.insert("package_seq".into(), seq.clone());
            let _ = client.send_record(&make_record(DATA_TYPE, fields));
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok(())
    }
}
