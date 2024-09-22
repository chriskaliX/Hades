use crate::cache::Transformer;
use crate::events::{execve::Execve, Event};
use anyhow::{anyhow, Context, Result};
use lazy_static::lazy_static;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    PerfBufferBuilder,
};
use log::*;
use sdk::{Client, Record};
use std::{
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod hades_skel {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/hades.skel.rs"
    ));
}

use hades_skel::*;

lazy_static! {
    pub static ref LOSS_CNT: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
}

pub struct Bpfmanager {}

impl Bpfmanager {
    pub fn new(mut client: Client) -> Result<Self> {
        Self::bump_rlimit()?;
        let skel_builder = HadesSkelBuilder::default();
        let open_skel: OpenHadesSkel<'_> =
            skel_builder.open().context("fail to open BPF program")?;
        let mut skel = open_skel.load().context("failed to load BPF program")?;
        skel.attach()?;
        /* loss cnt */
        let loss_cnt_c = LOSS_CNT.clone();
        /* transformer */
        let mut trans = Transformer::new();
        /* event handle wrap */
        let handle = |_cpu: i32, data: &[u8]| {
            let map = Execve::parse(&data[4..], &mut trans).unwrap();
            println!("{:?}", map);
        };

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
                let pld = rec.mut_data();
                pld.fields.insert(
                    "loss_cnt".to_string(),
                    loss_cnt_c.lock().unwrap().to_string(),
                );
                if let Err(err) = client.send_record(&rec) {
                    warn!("heartbeat will exit: {}", err);
                    break;
                };
                *LOSS_CNT.lock().unwrap() = 0;
                thread::sleep(Duration::from_secs(30))
            });
        let binding = skel.maps();
        let map = binding.events();
        let events = PerfBufferBuilder::new(map)
            .sample_cb(handle)
            .lost_cb(Self::handle_lost_events)
            .build()?;

        loop {
            events.poll(Duration::from_millis(100))?
        }
    }

    fn handle_lost_events(_cpu: i32, cnt: u64) {
        *LOSS_CNT.lock().unwrap() += cnt;
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
