/// NetInterface collector — data_type 3012.
/// Uses libc::getifaddrs.  Mirrors Go's event/systems/net_interface.go.
use std::collections::HashMap;
use std::ffi::CStr;

use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;

use crate::manager::{EventMode, IEvent};
use crate::event::{hash, make_record};

const DATA_TYPE: i32 = 3012;

pub struct NetInterface;

#[async_trait]
impl IEvent for NetInterface {
    fn name(&self)        -> &'static str { "net_interface" }
    fn data_type(&self)   -> i32          { DATA_TYPE }
    fn flag(&self)        -> EventMode    { EventMode::Periodic }
    fn immediately(&self) -> bool         { false }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        let seq    = hash();
        let ifaces = collect_interfaces();
        for info in ifaces {
            let mut fields = HashMap::new();
            fields.insert("name".into(),          info.name);
            fields.insert("flags".into(),         info.flags);
            fields.insert("hardware_addr".into(), info.hardware_addr);
            fields.insert("addrs".into(),         info.addrs.join(","));
            fields.insert("index".into(),         info.index.to_string());
            fields.insert("mtu".into(),           info.mtu.to_string());
            fields.insert("package_seq".into(),   seq.clone());
            let _ = client.send_record(&make_record(DATA_TYPE, fields));
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }
}

struct IfaceInfo {
    name:          String,
    flags:         String,
    hardware_addr: String,
    addrs:         Vec<String>,
    index:         i32,
    mtu:           i32,
}

fn collect_interfaces() -> Vec<IfaceInfo> {
    let mut map: std::collections::BTreeMap<String, IfaceInfo> = Default::default();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 { return Vec::new(); }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa  = &*cur;
            let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().to_string();
            let entry = map.entry(name.clone()).or_insert_with(|| {
                // Read index and MTU from sysfs
                let index = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
                    .ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                let mtu = std::fs::read_to_string(format!("/sys/class/net/{name}/mtu"))
                    .ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                let flags = format!("{:#010x}", ifa.ifa_flags);
                IfaceInfo { name: name.clone(), flags, hardware_addr: String::new(), addrs: Vec::new(), index, mtu }
            });

            if !ifa.ifa_addr.is_null() {
                let family = (*ifa.ifa_addr).sa_family as i32;
                match family {
                    libc::AF_INET => {
                        let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                        // get prefix length from netmask
                        if !ifa.ifa_netmask.is_null() {
                            let mask = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                            let prefix = u32::from_be(mask.sin_addr.s_addr).count_ones();
                            entry.addrs.push(format!("{ip}/{prefix}"));
                        } else {
                            entry.addrs.push(ip.to_string());
                        }
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                        entry.addrs.push(ip.to_string());
                    }
                    libc::AF_PACKET => {
                        let sll = &*(ifa.ifa_addr as *const libc::sockaddr_ll);
                        let mac: Vec<String> = sll.sll_addr[..6]
                            .iter().map(|b| format!("{b:02x}")).collect();
                        entry.hardware_addr = mac.join(":");
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    map.into_values().collect()
}
