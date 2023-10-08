use std::sync::atomic::{AtomicBool, Ordering};

use super::eguard_skel::EguardSkel;
use super::BpfProgram;
use anyhow::{Ok, Result};

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

    fn attach(&mut self, skel: &mut EguardSkel) -> Result<()> {
        let _dns_kprobe = skel
            .progs_mut()
            .kprobe_udp_sendmsg()
            .attach_kprobe(false, "udp_sendmsg")?;
        skel.links.kprobe_udp_sendmsg = Some(_dns_kprobe);
        self.status.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn detech(&mut self, skel: &mut EguardSkel) -> Result<()> {
        match &skel.links.kprobe_udp_sendmsg {
            None => {}
            Some(s) => s.detach()?,
        }
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

    fn handle_event(&self, _cpu: i32, _data: &[u8]) {
        todo!()
    }
}
