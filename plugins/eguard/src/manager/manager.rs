mod eguard_skel {
    include!("../bpf/eguard.skel.rs");
}
use crate::{
    config::config::Config,
    event::{eguard_skel::eguard_bss_types, BpfProgram},
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

        let perf_buffer = PerfBufferBuilder::new(skel.maps_mut().events())
            .sample_cb(Bpfmanager::handle_tc_event)
            .lost_cb(Bpfmanager::handle_tc_lost_events)
            .build()?;

        let thread_handle = spawn(move || {
            while running.load(Ordering::SeqCst) {
                if let Err(_) = perf_buffer.poll(Duration::from_millis(100)) {
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
}

impl Drop for Bpfmanager<'_> {
    fn drop(&mut self) {
        let events = &mut *EVENTS.write().unwrap();
        for (key, e) in events.iter_mut() {
            if let Some(skel) = self.skel.as_mut() {
                if let Err(err) = e.detach(skel) {
                    error!("drop event {} failed: {}", key, err);
                } else {
                    info!("drop event {} success", key);
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
