mod eguard_skel {
    include!("../../bpf/eguard.skel.rs");
}
use self::eguard_skel::eguard_bss_types;

use anyhow::Result;
use libc::{IPPROTO_TCP, IPPROTO_UDP};
use plain::Plain;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Action, CfgTrait, IpAddress, IpConfig};

const MAX_PORT_ARR: usize = 32;

/// Represents the protocol for egress policy.
/// ICMP will be supported in the feature
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum TcProtocol {
    ALL,
    TCP,
    UDP,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct TcPolicy {
    pub name: String,
    pub ingress: bool,
    pub address: String,
    pub protocol: TcProtocol,
    pub ports: Option<Vec<Value>>,
    pub action: Action,
    pub level: String,
}

unsafe impl Plain for eguard_bss_types::net_packet {}

impl CfgTrait for TcPolicy {
    fn to_bytes(&self) -> Result<(Vec<u8>, Vec<u8>)> {
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
            Action::DENY => 0,
            Action::LOG => 1,
        };
        value.ingress = self.ingress as u8;

        // parse protocol
        value.protocol = match self.protocol {
            TcProtocol::ALL => 0,
            TcProtocol::TCP => IPPROTO_TCP as u32,
            TcProtocol::UDP => IPPROTO_UDP as u32,
        };

        // parse ports
        if let Some(ports) = &self.ports {
            let mut range_index: usize = 0;
            let mut index: usize = 0;
            for (_, v) in ports.iter().enumerate().take(MAX_PORT_ARR) {
                match v {
                    serde_json::Value::Number(num) => {
                        if let Some(n) = num.as_u64() {
                            value.ports[index] = (n as u16).to_be();
                        }
                    }
                    serde_json::Value::String(s) => {
                        if s.contains('-') {
                            let fields: Vec<&str> = s.split('-').collect();
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
                            if let Ok(port) = s.parse::<u16>() {
                                value.ports[index] = port.to_be();
                                index += 1;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // flush to the map
        let value = unsafe { plain::as_bytes(&value) }.to_vec();
        Ok((key, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_egress_policy_to_bytes() {
        // Create a sample EgressPolicy
        let egress_policy = TcPolicy {
            name: String::from("Policy 1"),
            ingress: false,
            address: String::from("192.168.0.1/24"),
            protocol: TcProtocol::TCP,
            ports: Some(vec![
                serde_json::Value::String(String::from("80")),
                serde_json::Value::String(String::from("443")),
            ]),
            action: Action::LOG,
            level: String::from("high"),
        };

        // Convert EgressPolicy to bytes
        let result = egress_policy.to_bytes();

        // Assert the result
        assert!(result.is_ok());

        let (key, value) = result.unwrap();
        assert!(!key.is_empty());
        assert!(!value.is_empty());
    }
}
