/// Host-level metrics: hostname + network interface IP refresh.
///
/// Mirrors Go's `metrics/metric_host.go`.
/// Writes directly into `agent::host` so that all other code (gRPC, heartbeat)
/// always sees an up-to-date snapshot.
use std::time::Instant;

use crate::agent::host::{self, HostInfo};
use super::IMetric;

pub struct HostMetric;

impl IMetric for HostMetric {
    fn name(&self) -> &'static str { "host" }
    fn init(&self) -> anyhow::Result<()> { Ok(()) }

    fn flush(&self, _now: Instant) {
        let (private_ipv4, public_ipv4, private_ipv6, public_ipv6) = collect_ips();
        host::set(HostInfo {
            hostname: hostname(),
            private_ipv4,
            public_ipv4,
            private_ipv6,
            public_ipv6,
        });
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

/// RAII wrapper around the `getifaddrs` linked list.
/// `freeifaddrs` is called automatically via `Drop`, regardless of how the
/// enclosing scope exits — matching the pattern used by sysinfo and osquery.
struct IfAddrs(*mut libc::ifaddrs);

impl IfAddrs {
    fn get() -> Option<Self> {
        let mut p = std::ptr::null_mut();
        (unsafe { libc::getifaddrs(&mut p) } == 0).then_some(Self(p))
    }

    fn iter(&self) -> IfAddrsIter<'_> {
        IfAddrsIter { cur: self.0, _owner: self }
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        unsafe { libc::freeifaddrs(self.0) }
    }
}

struct IfAddrsIter<'a> {
    cur: *mut libc::ifaddrs,
    _owner: &'a IfAddrs,
}

impl<'a> Iterator for IfAddrsIter<'a> {
    type Item = *const libc::ifaddrs;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur.is_null() {
            return None;
        }
        let item = self.cur;
        self.cur = unsafe { (*item).ifa_next };
        Some(item)
    }
}

/// Enumerate all unicast IPv4 and IPv6 addresses via `getifaddrs(3)`.
/// Returns `(private_ipv4, public_ipv4, private_ipv6, public_ipv6)` as comma-joined strings.
fn collect_ips() -> (String, String, String, String) {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let Some(ifaddrs) = IfAddrs::get() else {
        return Default::default();
    };

    let (mut priv4, mut pub4) = (Vec::<String>::new(), Vec::<String>::new());
    let (mut priv6, mut pub6) = (Vec::<String>::new(), Vec::<String>::new());

    for ifa in ifaddrs.iter() {
        let sa = unsafe { (*ifa).ifa_addr };
        if sa.is_null() { continue; }

        match unsafe { (*sa).sa_family } as libc::c_int {
            libc::AF_INET => {
                let sin = unsafe { &*(sa as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() || ip.is_link_local() {
                    continue;
                }
                let bucket = if ip.is_private() { &mut priv4 } else { &mut pub4 };
                if bucket.len() < 5 { bucket.push(ip.to_string()); }
            }
            libc::AF_INET6 => {
                let sin6 = unsafe { &*(sa as *const libc::sockaddr_in6) };
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() || ip.is_unicast_link_local() {
                    continue;
                }
                // is_unique_local() covers fc00::/7 (both fc::/8 and fd::/8)
                let bucket = if ip.is_unique_local() { &mut priv6 } else { &mut pub6 };
                if bucket.len() < 5 { bucket.push(ip.to_string()); }
            }
            _ => {}
        }
    }

    (priv4.join(","), pub4.join(","), priv6.join(","), pub6.join(","))
}
