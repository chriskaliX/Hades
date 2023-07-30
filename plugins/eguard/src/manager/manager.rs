mod eguard_skel {
    include!("../bpf/eguard.skel.rs");
}
use crate::{event::BpfProgram, config::config::Config, TYPE_TC};
use anyhow::{anyhow, bail, Ok, Result};
use lazy_static::lazy_static;
use libbpf_rs::{skel::{SkelBuilder, OpenSkel}, PerfBufferBuilder};
use std::{collections::HashMap, sync::{Arc, Mutex, RwLock}, time::Duration, thread::{spawn, self}};
use log::*;

use crate::event::eguard_skel::{EguardSkel, EguardSkelBuilder};
use std::io::Cursor;
use byteorder::{ReadBytesExt, LittleEndian};

lazy_static! {
    static ref EVENTS: Arc<RwLock<HashMap<u32, Box<dyn BpfProgram + Send>>>> = Arc::new(RwLock::new(HashMap::new()));
}

pub struct Bpfmanager<'a> {
    skel: Option<EguardSkel<'a>>,
    running: Arc<Mutex<bool>>,
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
        let running = Arc::new(Mutex::new(true));
        let running_clone = Arc::clone(&running);

        // load the skel
        let mut skel = EguardSkelBuilder::default().open()?.load()?;
        let perf = PerfBufferBuilder::new(skel.maps_mut().events())
            .sample_cb(Bpfmanager::handle_event)
            .lost_cb(Bpfmanager::handle_lost_events)
            .build()?;
        let thread_handle = spawn(move || {
            while *running.lock().unwrap() {
                if let Err(_) = perf.poll(Duration::from_millis(100)) {
                    break;
                }
            }
        });
        let mgr = Bpfmanager {
            running: running_clone,
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

    fn handle_event(_cpu: i32, data: &[u8]) {
        if data.len() < 4 {
            return
        }
        let mut cursor = Cursor::new(&data[0..4]);
        let event_type = cursor.read_u32::<LittleEndian>().unwrap();
        let events = EVENTS.read().unwrap();
        events.get(&event_type).unwrap().handle_event(_cpu, data)
    }

    pub fn handle_lost_events(cpu: i32, count: u64) {
        error!("lost {} events on CPU {}", count, cpu);
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
        // waiting for thread exit
        if let Some(thread) = self.thread_handle.take() {
            *self.running.lock().unwrap() = false;
            thread.join().ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::tc::TcEvent;
    use crate::config::config::Config;

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
        let config = Config { tc: vec![] };
        assert!(bpfmanager.flush_config(config).is_ok());

        Ok(())
    }
}
