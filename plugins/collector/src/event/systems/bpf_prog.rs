/// BPF program enumerator — data_type 3014.
/// Trigger-only: lists all loaded eBPF programs via `aya::programs::loaded_programs()`.
use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use aya::programs::loaded_programs;
use procfs::KernelVersion;
use sdk::Client;

use crate::event::{hash, make_record};
use crate::manager::{EventMode, IEvent};

const DATA_TYPE:     i32   = 3014;
const MAX_BPF_PROGS: usize = 512;

pub struct BpfProg;

#[async_trait]
impl IEvent for BpfProg {
    fn name(&self)        -> &'static str { "bpf_prog" }
    fn data_type(&self)   -> i32          { DATA_TYPE }
    fn flag(&self)        -> EventMode    { EventMode::Trigger }
    fn immediately(&self) -> bool         { false }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        // BPF_PROG_GET_NEXT_ID requires kernel >= 4.13.
        // Cache the check result so /proc/sys/kernel/osrelease is only read once.
        static BPF_SUPPORTED: OnceLock<bool> = OnceLock::new();
        let supported = BPF_SUPPORTED.get_or_init(|| {
            KernelVersion::current()
                .map_or(true, |kv| kv >= KernelVersion::new(4, 13, 0))
        });
        if !supported {
            return Ok(());
        }

        let seq = hash();

        for info in loaded_programs().take(MAX_BPF_PROGS).flatten() {
            let fd    = info.fd().map(|f| f.as_fd().as_raw_fd()).unwrap_or(-1);
            let tag   = format!("{:016x}", info.tag());
            let ptype = info.program_type()
                .map(|t| format!("{t:?}").to_lowercase())
                .unwrap_or_else(|_| "unknown".into());

            let mut fields = HashMap::with_capacity(9);
            fields.insert("id".into(),          info.id().to_string());
            fields.insert("fd".into(),          fd.to_string());
            fields.insert("name".into(),        info.name_as_str().unwrap_or("").to_owned());
            fields.insert("type".into(),        ptype);
            fields.insert("tag".into(),         tag);
            fields.insert("run_count".into(),   info.run_count().to_string());
            fields.insert("run_time".into(),    format!("{:.2}", info.run_time().as_secs_f64()));
            fields.insert("pinned".into(),      "false".into());
            fields.insert("package_seq".into(), seq.clone());
            let _ = client.send_record(&make_record(DATA_TYPE, fields));

            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }
}

