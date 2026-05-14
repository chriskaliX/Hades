//! systems.rs — mirrors Go's event/systems.go (thin registration shim).

pub mod bpf_prog;
pub mod disk;
pub mod kmod;
pub mod net_interface;
pub mod systemd_unit;

use crate::manager::EventManager;
use std::time::Duration;

pub fn register(em: &mut EventManager) {
    em.add_event(kmod::Kmod,                          Duration::from_secs(6  * 3600));
    em.add_event(systemd_unit::SystemdUnit,           Duration::from_secs(24 * 3600));
    em.add_event(net_interface::NetInterface,         Duration::from_secs(24 * 3600));
    em.add_event(disk::Disk,                          Duration::from_secs(24 * 3600));
    em.add_event(bpf_prog::BpfProg,                   Duration::ZERO);   // Trigger only
}
