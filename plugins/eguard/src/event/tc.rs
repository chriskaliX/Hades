mod eguard_skel {
    include!("../bpf/eguard.skel.rs");
}
use crate::config::config::*;
use log::*;
use sdk::{Record, Payload};
use coarsetime::Clock;
use lazy_static::lazy_static;

use super::eguard_skel::EguardSkel;
use super::event::{TX, get_default_interface};
use super::BpfProgram;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::os::fd::AsFd;
use eguard_skel::*;
use libbpf_rs::{MapFlags, TcHook, TcHookBuilder, TC_EGRESS, TC_INGRESS};
use plain::Plain;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

lazy_static! {
    static ref TC_EVENT_HASH_MAP: Mutex<HashMap<&'static [u8], &'static [u8]>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
}

#[derive(Default)]
pub struct TcEvent {
    if_name: String,
    if_idx: i32,
    egress_hook: Option<TcHook>,
    ingress_hook: Option<TcHook>,
    status: AtomicBool,
}

unsafe impl Plain for eguard_bss_types::net_packet {}

impl<'a> TcEvent {
    pub fn new() -> Self {
        TcEvent::default()
    }

    // set the net interface
    pub fn set_if(&mut self, name: &str) -> Result<()> {
        self.if_name = name.to_owned();
        self.if_idx = nix::net::if_::if_nametoindex(name)? as i32;
        Ok(())
    }
}

impl<'a> BpfProgram for TcEvent {
    fn init(&mut self, skel: &mut EguardSkel) -> Result<()> {
        // check the if_name
        let interface = get_default_interface()?;
        info!("attach to interface: {}", interface);
        self.set_if(&interface)?;
        // load configuration if config.yaml exists
        #[cfg(feature = "debug")]
        if let Ok(config) = Config::from_file("config.yaml") {
            self.flush_config(config, skel)?;
        }
        Ok(())
    }

    // libbpf: Kernel error message: Exclusivity flag on, cannot modify
    // This message is harmless, reference: https://www.spinics.net/lists/bpf/msg44842.html
    fn attach(&mut self, skel: &mut EguardSkel) -> Result<()> {
        // generate the tc hook
        self.egress_hook = Some(
            TcHookBuilder::new(skel.progs().hades_egress().as_fd())
                .ifindex(self.if_idx.clone())
                .replace(true)
                .handle(1)
                .priority(1)
                .hook(TC_EGRESS),
        );
        self.ingress_hook = Some(
            TcHookBuilder::new(skel.progs().hades_ingress().as_fd())
                .ifindex(self.if_idx.clone())
                .replace(true)
                .handle(1)
                .priority(1)
                .hook(TC_INGRESS),
        );

        fn attach_hook(hook: &mut Option<libbpf_rs::TcHook>) -> Result<()> {
            if let Some(ref mut hook) = hook {
                hook.create().context("failed to create TC qdisc")?;
                hook.attach().context("failed to attach TC prog")?;
                hook.query()?;
            }
            Ok(())
        }
        attach_hook(&mut self.egress_hook)?;
        attach_hook(&mut self.ingress_hook)?;

        self.status.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// actually, it is destory
    fn detech(&mut self, skel: &mut EguardSkel) -> Result<()> {
        let mut destroy_all = libbpf_rs::TcHook::new(skel.progs().hades_egress().as_fd());
        destroy_all
            .ifindex(self.if_idx)
            .attach_point(TC_EGRESS | TC_INGRESS);
        destroy_all.destroy()?;
        Ok(())
    }

    fn flush_config(self: &TcEvent, cfgs: Config, skel:&mut EguardSkel) -> Result<()> {
        // cache up the vec
        let mut temp = HashMap::new();
        for v in cfgs.tc.into_iter() {
            let (key, value) = v.to_bytes()?;
            temp.insert(key, value);
        }
        // remove firstly
        let mut map = TC_EVENT_HASH_MAP.lock().unwrap();
        for (key, _) in map.clone().into_iter() {
            if !temp.contains_key(key) {
                skel.maps_mut()
                    .policy_map()
                    .delete(&key)?;
                map.remove(key);
            }
        }
        // add this to configurations
        for (key, value) in temp.into_iter() {
            if !map.contains_key(&key[..]) {
                skel.maps_mut()
                    .policy_map()
                    .update(&key, &value, MapFlags::ANY)?;
            }
        }
        Ok(())
    }

    fn status(&self) -> bool {
        return self.status.load(Ordering::Relaxed);
    }

    // event handlers
    fn handle_event(&self, _cpu: i32, data: &[u8]) {
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
        map.insert("ingress".to_string(), event.ingress.to_string());
    
        payload.set_fields(map);
        rec.set_data(payload);

        let lock = TX.lock().map_err(|e| error!("unable to acquire notification send channel: {}", e));
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
}
