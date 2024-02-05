mod hades_skel {
    include!("bpf/hades.skel.rs");
}
use anyhow::{anyhow, Context, Result};
use hades_skel::*;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    PerfBufferBuilder,
};
use log::*;
use sdk::{Client, Record};
use std::{
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::events::{execve::Execve, Event};

pub struct Bpfmanager {
    // loss_cnt: u64,
}

impl Bpfmanager {
    pub fn new(mut client: Client) -> Result<Self> {
        Self::bump_rlimit()?;
        let skel_builder = HadesSkelBuilder::default();
        let open_skel: OpenHadesSkel<'_> =
            skel_builder.open().context("fail to open BPF program")?;
        let mut skel = open_skel.load().context("failed to load BPF program")?;
        skel.attach()?;

        let _ = thread::Builder::new()
            .name("heartbeat".to_string())
            .spawn(move || loop {
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let mut rec = Record::new();
                rec.timestamp = timestamp as i64;
                rec.data_type = 900;
                {}
                if let Err(err) = client.send_record(&rec) {
                    warn!("heartbeat will exit: {}", err);
                    break;
                };
                thread::sleep(Duration::from_secs(30))
            });
        let binding = skel.maps();
        let map = binding.events();
        let events = PerfBufferBuilder::new(map)
            .sample_cb(Self::handle_events)
            .lost_cb(Self::handle_lost_events)
            .build()?;

        loop {
            events.poll(Duration::from_millis(100))?
        }
    }

    fn handle_events(_cpu: i32, data: &[u8]) {
        let map = Execve::parse(&data[4..]).unwrap();

        println!("{:?}", map);
    }

    fn handle_lost_events(_cpu: i32, count: u64) {
        println!("error: {:?}", count);
    }

    fn bump_rlimit() -> Result<()> {
        let rlimit = libc::rlimit {
            rlim_cur: 128 << 20,
            rlim_max: 128 << 20,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
            return Err(anyhow!("failed to increase rlimit"));
        }
        Ok(())
    }
}
