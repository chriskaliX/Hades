use std::sync::{Arc, Mutex};

use crossbeam::channel::Sender;
use lazy_static::lazy_static;
use sdk::Record;
use pnet::datalink::{self};
use anyhow::{anyhow, Ok, Result};

lazy_static! {
    pub static ref TX: Arc<Mutex<Option<Sender<Record>>>> = Arc::new(Mutex::new(None));
}

pub fn get_default_interface() -> Result<String> {
    let interface = datalink::interfaces()
        .into_iter()
        .filter(|interface| !interface.is_loopback() && !is_virtual_interface(&interface.name))
        .find(|interface| interface.is_up())
        .ok_or_else(|| anyhow!("Failed to find a suitable network interface"))?;
    Ok(interface.name.clone())
}

/// TODO: make this perfect
fn is_virtual_interface(name: &str) -> bool {
    name.starts_with("docker") ||
    false
}