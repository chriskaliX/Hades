mod eguard_skel {
    include!("../bpf/eguard.skel.rs");
}
use eguard_skel::*;
use libbpf_rs::{TcHookBuilder,TC_EGRESS, TcHook, PerfBufferBuilder, MapFlags};
use plain::Plain;
use super::BpfProgram;
use anyhow::{Result, Ok, bail, Context};
use std::net::{Ipv6Addr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{Mutex, Arc};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, spawn, sleep};
use core::time::Duration;

#[derive(Default)]
pub struct TcEvent<'a> {
    fd: i32,
    if_name: String,
    if_idx: i32,
    // skel and hook
    skel: Option<EguardSkel<'a>>,
    tchook: Option<TcHook>,
    // the thread
    thread_handle: Option<thread::JoinHandle<()>>,
    running: Arc<Mutex<bool>>,
    // event internal status
    stuatus: AtomicBool,
}

unsafe impl Plain for eguard_bss_types::net_packet {}

impl<'a> TcEvent<'a> {
    pub fn new() -> Self {
        TcEvent::default()
    }

    // set the net interface
    pub fn set_if(&mut self, name: &str) -> Result<()> {
        self.if_name = name.to_owned();
        self.if_idx = nix::net::if_::if_nametoindex(name)? as i32;
        Ok(())
    }

    fn exit_thread(&mut self) {
        if let Some(thread) = &self.thread_handle {
            *self.running.lock().unwrap() = false;
            loop {
                if thread.is_finished() {
                    break;
                }
                sleep(Duration::new(1, 0));
            }
        }        
    }

    // event handlers
    fn handle_event(_cpu: i32, data: &[u8]) {
        let mut event = eguard_bss_types::net_packet::default();
        plain::copy_from_bytes(&mut event, data).expect("data buffer was too short");
    
        let sip: Ipv6Addr;
        let dip: Ipv6Addr;

        unsafe {
            sip = Ipv6Addr::from(event.src_addr.in6_u.u6_addr8);
            dip = Ipv6Addr::from(event.dst_addr.in6_u.u6_addr8);
        }
        

        println!(
            "{:#?} {:#?}",
            sip.to_ipv4().unwrap().to_string(),
            dip.to_ipv4().unwrap().to_string(),
        );
    }

    fn handle_lost_events(cpu: i32, count: u64) {
        eprintln!("lost {count} events on CPU {cpu}");
    }
}

impl<'a> BpfProgram for TcEvent<'a> {
    fn init(&mut self) -> Result<()> {
        // check the if_name
        if self.if_name.is_empty() {
            bail!("if_name is empty")
        }
        // initialization
        let builder = EguardSkelBuilder::default();
        self.skel = Some(builder.open()?.load()?);
        let skel = self.skel.as_mut();
        if skel.is_none() {
            bail!("skel is invalid")
        }
        let skel = skel.unwrap();

        // generate the tc hook
        self.fd = skel.progs().hades_egress().fd();
        self.tchook = Some(TcHookBuilder::new()
            .fd(self.fd.clone())
            .ifindex(self.if_idx.clone())
            .replace(true)
            .handle(1)
            .priority(1)
            .hook(TC_EGRESS));
        
        // debugging here
        let value = (1 as u64).to_ne_bytes();
        let mut key = eguard_bss_types::policy_key::default();

        key.prefixlen = (96 as u32).to_le();
        key.addr = eguard_bss_types::in6_addr::default();
        key.addr.in6_u.u6_addr8 = Ipv6Addr::from_str("0000:0000:0000:0000:0000:0000:192.168.1.1").unwrap().octets();

        let key_bytes: &[u8];
        unsafe { key_bytes = any_as_u8_slice(&key) };
        skel.maps_mut().EGRESS_POLICY_MAP().update(key_bytes, &value, MapFlags::ANY)?;

        // consume the perf continusiouly
        let perf = PerfBufferBuilder::new(skel.maps_mut().events())
            .sample_cb(TcEvent::handle_event)
            .lost_cb(TcEvent::handle_lost_events)
            .build()?;
        let running = Arc::new(Mutex::new(true));
        let running_clone = running.clone();
        self.running = running_clone;
        // spawn the consumer
        let thread_job = spawn(move || {
            while *running.lock().unwrap() {
                if let Err(_) = perf.poll(Duration::from_millis(100)) {
                    break
                }
            }
        });
        self.thread_handle = Some(thread_job);
        Ok(())
    }

    // libbpf: Kernel error message: Exclusivity flag on, cannot modify
    // This message is harmless, reference: https://www.spinics.net/lists/bpf/msg44842.html
    fn attach(&mut self) -> Result<()> {
        if let Some(mut hook) = self.tchook {
            hook
                .create()
                .context("failed to create egress TC qdisc")?;  
            hook
                .attach()
                .context("failed to attach egress TC prog")?;
            // check if the hook isready
            if let Err(e) = hook.query() {
                self.exit_thread();
                bail!(e)
            }
            if self.skel.is_none() {
                self.exit_thread();
                bail!("skel is invalid")
            }
        } else {
            self.exit_thread();
            bail!("tchook not exists")
        }
        self.stuatus.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn detech(&mut self) -> Result<()> {
        if let Some(mut hook) = self.tchook {
            hook.detach()?;
            hook.destroy()?;
            self.exit_thread();
            self.stuatus.store(false, Ordering::Relaxed);
        } else {
            bail!("tchook not exists")
        }
        Ok(())
    }

    fn status(&self) -> bool {
        return self.stuatus.load(Ordering::Relaxed);
    }
}

pub unsafe fn serialize_row<T: Sized>(src: &T) ->&[u8] {
    ::std::slice::from_raw_parts((src as *const T) as *const u8, ::std::mem::size_of::<T>())      
}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::core::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::core::mem::size_of::<T>(),
    )
}