mod eguard_skel {
    include!("../bpf/eguard.skel.rs");
}
use crate::config::config::*;
use crate::config::ip_config::IpConfig;
use log::*;
use sdk::{Record, Payload};
use coarsetime::Clock;

use super::event::TX;
use super::ip_address::IpAddress;
use super::BpfProgram;
use anyhow::{bail, Context, Result};
use core::time::Duration;
use std::collections::HashMap;
use eguard_skel::*;
use libbpf_rs::{MapFlags, PerfBufferBuilder, TcHook, TcHookBuilder, TC_EGRESS};
use libc::{IPPROTO_TCP, IPPROTO_UDP};
use plain::Plain;
use std::fs;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, spawn};

#[derive(Default)]
pub struct TcEvent<'a> {
    fd: i32,
    if_name: String,
    if_idx: i32,
    skel: Option<EguardSkel<'a>>, // skel and hook
    tchook: Option<TcHook>,
    thread_handle: Option<thread::JoinHandle<()>>,
    running: Arc<Mutex<bool>>,
    stuatus: AtomicBool,
}

unsafe impl Plain for eguard_bss_types::net_packet {}
const MAX_PORT_ARR: usize = 32;

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

    // flush config from Vec<Policy>, delete firstly, then add
    pub fn flush_config(&mut self, cfg: EgressPolicy) -> Result<()> {
        // delete the cfgs if not in the new ones
        let mut key = eguard_bss_types::policy_key::default();
        let mut value = eguard_bss_types::policy_value::default();
        
        // parse key
        let ip = IpConfig::new(&cfg.address)?;
        key.prefixlen = ip.prefixlen.try_into().unwrap_or(128);
        key.addr = eguard_bss_types::in6_addr::default();
        let address = IpAddress::from_ip(ip.subnet);
        key.addr.in6_u.u6_addr8 = address.0;
        let key = unsafe { plain::as_bytes(&key) };

        // parse value
        value.action = match cfg.action {
            EgressAction::DENY => 0,
            EgressAction::LOG => 1,
        };

        // parse protocol
        value.protocol = match cfg.protocol {
            EgressProtocol::ALL => 0,
            EgressProtocol::TCP => IPPROTO_TCP as u32,
            EgressProtocol::UDP => IPPROTO_UDP as u32,
        };
        // parse ports
        if let Some(ports) = cfg.ports {
            let mut range_index: usize = 0;
            let mut index: usize = 0;
            for (_, v) in ports.iter().enumerate().take(MAX_PORT_ARR) {
                if v.contains('-') {
                    let fields: Vec<&str> = v.split('-').collect();
                    if fields.len() == 2 {
                        let start: u16 = match fields[0].parse() {
                            Ok(s) => s,
                            _ => continue,
                        };
                        let end: u16 = match fields[1].parse() {
                            Ok(e) => e,
                            _ => continue,
                        };
                        if end >= start {
                            // notice: little-endian
                            value.ports_range[2 * range_index] = start;
                            value.ports_range[2 * range_index + 1] = end;
                            range_index += 1;
                        }
                    }
                } else {
                    if let Ok(port) = v.parse::<u16>() {
                        value.ports[index] = port.to_be();
                        index += 1;
                    }
                }
            }            
        }


        // flush to the map
        let value = unsafe { plain::as_bytes(&value) };
        self.skel
            .as_mut()
            .unwrap()
            .maps_mut()
            .EGRESS_POLICY_MAP()
            .update(&key, &value, MapFlags::ANY)?;

        Ok(())
    }

    fn exit_thread(&mut self) {
        if let Some(thread) = self.thread_handle.take() {
            *self.running.lock().unwrap() = false;
            thread.join().ok();
        }
    }

    // event handlers
    fn handle_event(_cpu: i32, data: &[u8]) {
        let mut event = eguard_bss_types::net_packet::default();
        if let Err(e) = plain::copy_from_bytes(&mut event, data) {
            error!("copy bytes from kernel failed: {:?}", e);
            return;
        };
    
        let sip: Ipv6Addr;
        let dip: Ipv6Addr;
    
        unsafe {
            sip = Ipv6Addr::from(event.src_addr.in6_u.u6_addr8);
            dip = Ipv6Addr::from(event.dst_addr.in6_u.u6_addr8);
        }
    
        let mut rec = Record::new();
        let mut payload = Payload::new();
    
        rec.set_data_type(3200);
        rec.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
    
        let mut map = HashMap::with_capacity(7);
        map.insert("ifindex".to_string(), event.ifindex.to_string());
        map.insert("protocol".to_string(), event.protocol.to_string());
        map.insert("sip".to_string(), match sip.to_ipv4() {
            Some(s) => s.to_string(),
            None => sip.to_string(),
        });
        map.insert("sport".to_string(), event.src_port.to_be().to_string());
        map.insert("dip".to_string(), match dip.to_ipv4() {
            Some(s) => s.to_string(),
            None => dip.to_string(),
        });
        map.insert("dport".to_string(), event.dst_port.to_be().to_string());
    
        let action = if event.action == 0 { "deny" } else { "log" };
        map.insert("action".to_string(), action.to_string());
    
        payload.set_fields(map);
        rec.set_data(payload);

        let mut lock = TX
            .lock()
            .map_err(|e| error!("unable to acquire notification send channel: {}", e)).unwrap();
        match &mut *lock {
            Some(sender) => {
                if let Err(err) = sender.send(rec) {
                    error!("send failed: {}", err);
                    return;
                }
            }
            None => return,
        }
    }

    fn handle_lost_events(cpu: i32, count: u64) {
        error!("lost {} events on CPU {}", count, cpu);
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
        let skel = self.skel.as_mut().expect("Failed to initialize skel");

        // generate the tc hook
        self.fd = skel.progs().hades_egress().fd();
        self.tchook = Some(
            TcHookBuilder::new()
                .fd(self.fd.clone())
                .ifindex(self.if_idx.clone())
                .replace(true)
                .handle(1)
                .priority(1)
                .hook(TC_EGRESS),
        );

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
                    break;
                }
            }
        });
        self.thread_handle = Some(thread_job);

        // load configuration if config.yaml exists
        if let Ok(yaml_string) = fs::read_to_string("config.yaml") {
            let config: Config = serde_yaml::from_str(&yaml_string)?;
            for v in config.egress.into_iter() {
                self.flush_config(v)?;
            }
        }

        Ok(())
    }

    // libbpf: Kernel error message: Exclusivity flag on, cannot modify
    // This message is harmless, reference: https://www.spinics.net/lists/bpf/msg44842.html
    fn attach(&mut self) -> Result<()> {
        if let Some(mut hook) = self.tchook {
            hook.create().context("failed to create egress TC qdisc")?;
            hook.attach().context("failed to attach egress TC prog")?;
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
