use std::fs;
use std::result::Result::Ok;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use crossbeam::channel::Sender;
use lazy_static::lazy_static;
use pnet::datalink::{self};
use sdk::Record;

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

fn is_virtual_interface(name: &str) -> bool {
    // https://unix.stackexchange.com/questions/57309/how-can-i-tell-whether-a-network-interface-is-physical-device-or-virtual-alia
    // Note
    // Physical interfaces would show like /sys/device/{id}... while virtual ones like /sys/device/virtual/net/
    let entries = match fs::read_dir("/sys/devices/virtual/net/") {
        Ok(entries) => entries,
        Err(_) => return false,
    };

    entries
        .filter_map(|entry| {
            entry
                .ok()
                .and_then(|e| e.file_name().to_string_lossy().into_owned().into())
        })
        .any(|entry_name: String| entry_name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_virtual_interface() {
        assert!(is_virtual_interface("lo") == true);
    }
}
