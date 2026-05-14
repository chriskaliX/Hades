//! networks.rs — mirrors Go's event/networks.go (thin registration shim).

pub mod iptables;
pub mod socket;

use crate::manager::EventManager;
use std::time::Duration;

pub fn register(em: &mut EventManager) {
    em.add_event(socket::Socket,       Duration::from_secs(15 * 60));
    em.add_event(iptables::Iptables,   Duration::from_secs(24 * 3600));
}
