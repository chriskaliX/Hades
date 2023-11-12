mod eguard_skel {
    include!("../bpf/eguard.skel.rs");
}
use crate::{
    config::config::Config,
    event::{eguard_skel::eguard_bss_types, event::TX, BpfProgram},
    TYPE_TC,
};
use anyhow::{anyhow, bail, Ok, Result};
use lazy_static::lazy_static;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    PerfBufferBuilder,
};
use log::*;
use plain::Plain;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    thread::{self, spawn},
    time::Duration,
};

use crate::event::eguard_skel::{EguardSkel, EguardSkelBuilder};
use byteorder::{LittleEndian, ReadBytesExt};
use coarsetime::Clock;
use sdk::{Payload, Record};
use std::io::Cursor;

lazy_static! {
    static ref EVENTS: Arc<RwLock<HashMap<u32, Box<dyn BpfProgram + Send>>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

unsafe impl Plain for eguard_bss_types::data_context {}

pub struct Bpfmanager<'a> {
    skel: Option<EguardSkel<'a>>,
    running: Arc<AtomicBool>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl Bpfmanager<'_> {
    // bump memlock rlimit
    pub fn bump_memlock_rlimit() -> Result<()> {
        let rlimit = libc::rlimit {
            rlim_cur: 128 << 20,
            rlim_max: 128 << 20,
        };

        if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
            bail!("failed to increase rlimit");
        }

        Ok(())
    }

    // new bpfmanager
    // and load the skel at the same time
    pub fn new() -> Result<Self> {
        let running = Arc::new(AtomicBool::new(true));
        let r_clone = Arc::clone(&running);

        // load the skel
        let mut skel = EguardSkelBuilder::default().open()?.load()?;

        let network_perf = PerfBufferBuilder::new(skel.maps_mut().events())
            .sample_cb(Bpfmanager::handle_tc_event)
            .lost_cb(Bpfmanager::handle_tc_lost_events)
            .build()?;
        let exec_perf = PerfBufferBuilder::new(skel.maps_mut().exec_events())
            .sample_cb(Bpfmanager::handle_exec_event)
            .lost_cb(Bpfmanager::handle_exec_lost_events)
            .build()?;

        let thread_handle = spawn(move || {
            while running.load(Ordering::SeqCst) {
                if let Err(_) = network_perf.poll(Duration::from_millis(100)) {
                    break;
                }
                if let Err(_) = exec_perf.poll(Duration::from_millis(100)) {
                    break;
                }
            }
        });
        let mgr = Bpfmanager {
            running: r_clone,
            thread_handle: Some(thread_handle),
            skel: Some(skel),
        };
        Ok(mgr)
    }

    // Load the bpfprogram into the hashmap
    // @param - key - the id of the program
    //        - program - the BPF program implement BpfTrait
    pub fn load_program(&mut self, key: u32, prog: Box<dyn BpfProgram + Send>) {
        EVENTS.write().unwrap().insert(key.to_owned(), prog);
    }

    // Start the bpfprogram inside the events map
    // @param - key - the id of the program
    pub fn start_program(&mut self, key: u32) -> Result<()> {
        let mut binding = EVENTS.write().unwrap();
        let program = binding.get_mut(&key).ok_or_else(|| anyhow!("invalid"))?;
        if program.status() {
            bail!("{} is running", key)
        }
        if let Some(skel) = self.skel.as_mut() {
            program.init(skel)?;
            program.attach(skel)?;
        }

        Ok(())
    }

    // Wrapper of the load_program and start_program
    pub fn autoload(&mut self, key: u32, prog: Box<dyn BpfProgram + Send>) -> Result<()> {
        self.load_program(key, prog);
        self.start_program(key)
    }

    // Flush and replace the configuration
    // @param - conf - the full configuration
    pub fn flush_config(&mut self, conf: Config) -> Result<()> {
        // flush egress
        if let Some(v) = EVENTS.read().unwrap().get(&TYPE_TC) {
            if let Some(skel) = self.skel.as_mut() {
                v.flush_config(conf, skel)?
            }
        }
        Ok(())
    }

    /// Basicly, there are only two kind of perf events
    /// First one is the tc(xdp) event, which contains only network information
    /// The other one is the general event like kprobe, which would carry with the process
    /// context like uid, pid and something else
    fn handle_tc_event(_cpu: i32, data: &[u8]) {
        if data.len() < 4 {
            return;
        }
        let mut cursor = Cursor::new(&data[0..4]);
        let event_type = cursor.read_u32::<LittleEndian>().unwrap();
        let events = EVENTS.read().unwrap();
        events.get(&event_type).unwrap().handle_event(_cpu, data)
    }

    fn handle_tc_lost_events(cpu: i32, count: u64) {
        error!("lost tc {} events on CPU {}", count, cpu);
    }

    /// working on this
    fn handle_exec_event(_cpu: i32, data: &[u8]) {
        // parse the context
        let mut context = eguard_bss_types::data_context::default();
        plain::copy_from_bytes(&mut context, data).expect("context decode failed");
        let mut map = HashMap::new();
        map.insert("cgroupid".to_string(), context.cgroup_id.to_string());
        map.insert("pns".to_string(), context.pns.to_string());
        map.insert("pid".to_string(), context.pid.to_string());
        map.insert("tid".to_string(), context.tid.to_string());
        map.insert("uid".to_string(), context.uid.to_string());
        map.insert("gid".to_string(), context.gid.to_string());
        map.insert("ppid".to_string(), context.ppid.to_string());
        map.insert("pgid".to_string(), context.pgid.to_string());
        map.insert("sessionid".to_string(), context.sessionid.to_string());
        let comm: &[u8] = unsafe { std::mem::transmute(&context.comm[..]) };
        map.insert("comm".to_string(), trim_null_chars(comm));
        let pcomm: &[u8] = unsafe { std::mem::transmute(&context.pcomm[..]) };
        map.insert("pcomm".to_string(), trim_null_chars(pcomm));
        let nodename: &[u8] = unsafe { std::mem::transmute(&context.nodename[..]) };
        map.insert("nodename".to_string(), trim_null_chars(nodename));

        let mut rec = Record::new();
        let mut pld = Payload::new();
        pld.set_fields(map);
        rec.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        rec.set_data(pld);
        rec.data_type = context.dt as i32;
        let lock = TX
            .lock()
            .map_err(|e| error!("unable to acquire notification send channel: {}", e));
        match &mut *lock.unwrap() {
            Some(sender) => {
                if let Err(err) = sender.send(rec) {
                    error!("send failed: {}", err);
                    return;
                }
            }
            None => return,
        }
    }

    fn handle_exec_lost_events(cpu: i32, count: u64) {
        error!("lost exec_events {} events on CPU {}", count, cpu);
    }
}

impl Drop for Bpfmanager<'_> {
    fn drop(&mut self) {
        let events = &mut *EVENTS.write().unwrap();
        for (key, e) in events.iter_mut() {
            if let Some(skel) = self.skel.as_mut() {
                if let Err(err) = e.detech(skel) {
                    error!("drop event {} failed: {}", key, err);
                }
            }
        }
        self.running.store(false, Ordering::SeqCst);
        // waiting for thread exit
        if let Some(thread) = self.thread_handle.take() {
            thread.join().ok();
        }

        debug!("has dropped bpfmanager from thread");
    }
}

fn trim_null_chars(data: &[u8]) -> String {
    String::from_utf8_lossy(data)
        .to_string()
        .trim_end_matches('\0')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::config::Config;
    use crate::event::tc::TcEvent;

    #[test]
    fn test_bpfmanager() -> Result<()> {
        // Create a new Bpfmanager instance
        let mut bpfmanager = Bpfmanager::new()?;

        // Load a BPF program into the Bpfmanager
        let egress_program = TcEvent::new();
        bpfmanager.load_program(TYPE_TC, Box::new(egress_program));

        // Start a loaded BPF program
        assert!(bpfmanager.start_program(TYPE_TC).is_ok());

        // Try to start the same program again (should fail)
        assert!(bpfmanager.start_program(TYPE_TC).is_err());

        // Flush the config
        let config = Config {
            tc: vec![],
            dns: vec![],
        };
        assert!(bpfmanager.flush_config(config).is_ok());

        Ok(())
    }
}
