pub(crate) mod eguard_skel {
    include!("../bpf/eguard.skel.rs");
}

use anyhow::Result;
use crate::config::config::Config;

use self::eguard_skel::EguardSkel;

pub mod tc;
pub mod xdp;
pub mod event;
pub mod ip_address;

pub trait BpfProgram: Sync {
    /// init he bpf program
    fn init(&mut self, skel: &mut EguardSkel) -> Result<()>;

    /// attach bpf binary
    fn attach(&mut self, skel: &mut EguardSkel) -> Result<()>;

    /// detech the binary, wrapper the destory method inside if it is needed
    fn detech(&mut self, skel: &mut EguardSkel) -> Result<()>;

    /// status of the bpf program
    fn status(&self) -> bool;

    /// flush configuration into this
    fn flush_config(&self, config: Config, skel: &mut EguardSkel) -> Result<()>;

    fn handle_event(&self, _cpu: i32, data: &[u8]);
}
