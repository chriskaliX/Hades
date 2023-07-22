mod eguard_skel {
    include!("../bpf/eguard.skel.rs");
}

use plain::Plain;
use serde::{Deserialize, Serialize};
use anyhow:: Result;
use libc::{IPPROTO_TCP, IPPROTO_UDP};
use crate::event::ip_address::IpAddress;
use self::eguard_skel::eguard_bss_types;
use super::ip_config::IpConfig;

const MAX_PORT_ARR: usize = 32;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum EgressAction {
    DENY,
    LOG,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum EgressProtocol {
    ALL,
    TCP,
    UDP,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub egress: Vec<EgressPolicy>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct EgressPolicy {
    pub name: String,
    pub address: String,
    pub protocol: EgressProtocol,
    pub ports: Option<Vec<String>>,
    pub action: EgressAction,
    pub level: String,
}

unsafe impl Plain for eguard_bss_types::net_packet {}

impl EgressPolicy {
    pub fn to_bytes(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut key = eguard_bss_types::policy_key::default();
        let mut value = eguard_bss_types::policy_value::default();

        // parse key
        let ip = IpConfig::new(&self.address)?;
        key.prefixlen = ip.prefixlen.try_into().unwrap_or(128);
        key.addr = eguard_bss_types::in6_addr::default();
        let address = IpAddress::from_ip(ip.subnet);
        key.addr.in6_u.u6_addr8 = address.0;
        let key = unsafe { plain::as_bytes(&key) }.to_vec();

        // parse value
        value.action = match self.action {
            EgressAction::DENY => 0,
            EgressAction::LOG => 1,
        };

        // parse protocol
        value.protocol = match self.protocol {
            EgressProtocol::ALL => 0,
            EgressProtocol::TCP => IPPROTO_TCP as u32,
            EgressProtocol::UDP => IPPROTO_UDP as u32,
        };

        // parse ports
        if let Some(ports) = &self.ports {
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
        let value = unsafe { plain::as_bytes(&value) }.to_vec();
        Ok((key, value))
    }
}