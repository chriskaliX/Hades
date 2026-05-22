use crate::cache::Transformer;
use crate::events::parse_event;
use crate::scanner;
use anyhow::{anyhow, Context, Result};
use lazy_static::lazy_static;
use libbpf_rs::{
    skel::{OpenSkel, Skel, SkelBuilder},
    MapCore, MapFlags, PerfBufferBuilder,
};
use log::*;
use sdk::{Client, Payload, Record};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    sync::Arc,
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
    pub static ref LOSS_CNT: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
}

pub struct Bpfmanager {}

impl Bpfmanager {
    pub fn new(client: Client) -> Result<Self> {
        Self::bump_rlimit()?;

        let skel_builder = HadesSkelBuilder::default();
        // libbpf-rs 0.24+ requires passing a MaybeUninit storage to open().
        // The storage must outlive `skel` – both are declared in this scope.
        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = skel_builder
            .open(&mut open_object)
            .context("Skel open failed")?;

        // Some LSM hooks (e.g. security_socket_bind) are not compiled into all
        // kernels (notably WSL2).  Disable the probe if the symbol is absent to
        // avoid a hard ENOENT failure at attach time.
        if !std::fs::read_to_string("/proc/kallsyms")
            .unwrap_or_default()
            .contains(" security_socket_bind\n")
        {
            open_skel
                .progs
                .kprobe_security_socket_bind
                .set_autoload(false);
            warn!("security_socket_bind not found in kallsyms, skipping kprobe");
        }

        // trigger_sct_scan and trigger_module_scan are self-uprobes (attach to
        // this binary's own function symbols).  uretprobe_bash_readline attaches
        // to bash.  None have a binary-path in the SEC annotation, so libbpf
        // cannot auto-attach them; they are either attached manually later or
        // skipped on kernels where the target is not present.
        open_skel
            .progs
            .trigger_sct_scan
            .set_autoload(false);
        open_skel
            .progs
            .trigger_module_scan
            .set_autoload(false);
        open_skel
            .progs
            .uretprobe_bash_readline
            .set_autoload(false);

        let mut skel = open_skel.load().context("Load skel failed")?;

        skel.attach().context("Skel attach failed")?;

        // P2-3: Exclude this process from eBPF monitoring to avoid
        // self-observing feedback loops.
        let my_pid = unsafe { libc::getpid() as u32 };
        let val: u32 = 0;
        skel.maps
            .pid_filter
            .update(
                &my_pid.to_ne_bytes(),
                &val.to_ne_bytes(),
                MapFlags::ANY,
            )
            .context("Failed to add self to pid_filter")?;

        let mut trans = Transformer::new();
        let mut sender = client.clone();

        /* event handle wrap */
        let handle = move |_cpu: i32, data: &[u8]| {
            if data.len() < 4 {
                return;
            }

            let data_type = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            match parse_event(data_type, &data[4..], &mut trans) {
                Ok(Some(fields)) => {
                    let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
                        Ok(v) => v.as_secs() as i64,
                        Err(_) => 0,
                    };
                    let mut rec = Record::default();
                    rec.timestamp = timestamp;
                    rec.data_type = data_type as i32;
                    let pld = rec.data.get_or_insert_with(Payload::default);
                    pld.fields = fields;
                    if let Err(err) = sender.send_record(&rec) {
                        warn!("send record failed, dt={}: {}", data_type, err);
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    debug!("parse event failed, dt={}: {}", data_type, err);
                }
            }
        };

        Self::start_heartbeat_thread(client)?;
        Self::start_rootkit_scan_thread()?;

        // In libbpf-rs 0.24+, maps are public struct fields (not method calls).
        // PerfBufferBuilder accepts any type implementing MapCore.
        let events = PerfBufferBuilder::new(&skel.maps.events)
            .sample_cb(handle)
            .lost_cb(Self::handle_lost_events)
            .build()?;

        loop {
            events.poll(Duration::from_millis(100))?
        }
    }

    fn handle_lost_events(_cpu: i32, cnt: u64) {
        LOSS_CNT.fetch_add(cnt, Ordering::SeqCst);
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

    fn start_heartbeat_thread(mut client: Client) -> Result<()> {
        thread::Builder::new()
            .name("heartbeat".to_string())
            .spawn(move || loop {
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;

                let mut rec = Record::default();
                rec.timestamp = timestamp;
                rec.data_type = 900;

                let pld = rec.data.get_or_insert_with(Payload::default);
                let loss_count = LOSS_CNT.load(Ordering::SeqCst);
                pld.fields
                    .insert("loss_cnt".to_string(), loss_count.to_string());

                if let Err(err) = client.send_record(&rec) {
                    warn!("Heartbeat will exit: {}", err);
                    break;
                }

                LOSS_CNT.store(0, Ordering::SeqCst); // Reset the loss counter
                thread::sleep(Duration::from_secs(30));
            })
            .context("Failed to spawn heartbeat thread")?;

        Ok(())
    }

    fn start_rootkit_scan_thread() -> Result<()> {
        thread::Builder::new()
            .name("rootkit-scanner".to_string())
            .spawn(move || {
                scanner::run_scan();
                loop {
                    thread::sleep(Duration::from_secs(600));
                    scanner::run_scan();
                }
            })
            .context("Failed to spawn rootkit scanner thread")?;
        Ok(())
    }
}
