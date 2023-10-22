mod eguard_skel {
    include!("../bpf/eguard.skel.rs");
}
use coarsetime::Clock;
use eguard_skel::*;

use std::{
    collections::HashMap,
    net::Ipv6Addr,
    sync::atomic::{AtomicBool, Ordering},
};

use super::eguard_skel::EguardSkel;
use super::event::TX;
use super::BpfProgram;
use anyhow::{Ok, Result};
use log::*;
use plain::Plain;
use sdk::{Payload, Record};

unsafe impl Plain for eguard_bss_types::net_context {}
unsafe impl Plain for eguard_bss_types::dnshdr {}

/// Notice: This is not working for now
#[derive(Default)]
pub struct DnsEvent {
    status: AtomicBool,
}

impl<'a> DnsEvent {
    pub fn new() -> Self {
        DnsEvent::default()
    }
}

impl<'a> BpfProgram for DnsEvent {
    fn init(&mut self, _skel: &mut EguardSkel) -> Result<()> {
        Ok(())
    }

    fn attach(&mut self, _skel: &mut EguardSkel) -> Result<()> {
        self.status.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn detech(&mut self, _skel: &mut EguardSkel) -> Result<()> {
        self.status.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn status(&self) -> bool {
        return self.status.load(Ordering::SeqCst);
    }

    fn flush_config(
        &self,
        _config: crate::config::config::Config,
        _skel: &mut EguardSkel,
    ) -> Result<()> {
        Ok(())
    }

    fn handle_event(&self, _cpu: i32, data: &[u8]) {
        let mut event = eguard_bss_types::net_context::default();
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

        let mut rec: Record = Record::new();
        let mut payload: Payload = Payload::new();
        rec.set_data_type(3201);
        rec.set_timestamp(Clock::now_since_epoch().as_secs() as i64);
        let mut map = HashMap::with_capacity(7);
        map.insert("ifindex".to_string(), event.ifindex.to_string());
        map.insert("protocol".to_string(), event.protocol.to_string());
        map.insert(
            "dip".to_string(),
            match sip.to_ipv4() {
                Some(s) => s.to_string(),
                None => dip.to_string(),
            },
        );
        map.insert("sport".to_string(), event.src_port.to_be().to_string());
        map.insert(
            "dip".to_string(),
            match dip.to_ipv4() {
                Some(s) => s.to_string(),
                None => dip.to_string(),
            },
        );
        map.insert("dport".to_string(), event.dst_port.to_be().to_string());
        let action = if event.action == 0 { "deny" } else { "log" };
        map.insert("action".to_string(), action.to_string());
        map.insert("ingress".to_string(), event.ingress.to_string());

        // get the dns header
        let data = &data[64..];
        let mut dnshdr = eguard_bss_types::dnshdr::default();
        if let Err(e) = plain::copy_from_bytes(&mut dnshdr, data) {
            error!("copy bytes from kernel failed: {:?}", e);
            return;
        };

        let data = &data[12..];
        let mut length: u16 = 0;
        if let Err(e) = plain::copy_from_bytes(&mut length, data) {
            error!("copy bytes from kernel failed: {:?}", e);
            return;
        };

        let data = &data[2..];
        let domain: &mut [u8] = &mut vec![0; length as usize][..];
        if let Err(e) = plain::copy_from_bytes(domain, data) {
            error!("copy bytes from kernel failed: {:?}", e);
            return;
        }

        map.insert(
            "domain".to_string(),
            String::from_utf8_lossy(domain).to_string(),
        );
        payload.set_fields(map);
        rec.set_data(payload);

        let lock = TX
            .lock()
            .map_err(|e| error!("unable to acquire notification send channel: {}", e));
        if let Some(sender) = &mut *lock.unwrap() {
            if let Err(err) = sender.send(rec) {
                error!("send failed: {}", err);
                return;
            }
        }
    }
}
