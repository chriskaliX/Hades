pub(crate) mod eguard_skel {
    include!("../bpf/eguard.skel.rs");
}

use crate::config::config::*;
use crate::config::parser::CfgTrait;
use anyhow::Result;

use self::eguard_skel::EguardSkel;
use libbpf_rs::{Map, MapFlags};
use std::collections::HashMap;
use std::sync::MutexGuard;

pub mod dns;
pub mod event;
pub mod tc;
pub mod xdp;

pub trait BpfProgram: Sync {
    /// init he bpf program
    fn init(&mut self, skel: &mut EguardSkel) -> Result<()>;

    /// attach bpf binary
    fn attach(&mut self, skel: &mut EguardSkel) -> Result<()>;

    /// detach the binary, wrapper the destory method inside if it is needed
    fn detach(&mut self, skel: &mut EguardSkel) -> Result<()>;

    /// status of the bpf program
    fn status(&self) -> bool;

    /// flush configuration into this
    fn flush_config(&self, config: Config, skel: &mut EguardSkel) -> Result<()>;

    fn handle_event(&self, _cpu: i32, data: &[u8]);
}

fn update_map<T>(
    cache: Vec<T>,
    mut map: MutexGuard<'_, HashMap<&[u8], &[u8]>>,
    bpfmap: &mut Map,
) -> Result<()>
where
    T: CfgTrait,
{
    // local cache up for bytes
    let mut m = HashMap::new();
    for v in cache {
        let (key, value) = v.to_bytes()?;
        m.insert(key, value);
    }

    let map_clone: HashMap<&[u8], &[u8]> = map.clone();
    for (key, _) in map_clone.into_iter() {
        if !m.contains_key(key) {
            bpfmap.delete(&key)?;
            map.remove(&key);
        }
    }

    for (key, value) in m.into_iter() {
        if !map.contains_key(&key[..]) {
            bpfmap.update(&key, &value, MapFlags::ANY)?;
        }
    }

    Ok(())
}
