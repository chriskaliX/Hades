use crate::events::{ENOTFOUND, ERATELIMIT};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use moka::sync::Cache;
use std::{fs::read, num::NonZeroU32, str};

pub struct NsCache {
    cache: Cache<u32, String>,
    rlimit: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
}

impl NsCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cache: Cache::new(cap as u64),
            rlimit: RateLimiter::direct(Quota::per_second(NonZeroU32::new(25).unwrap())),
        }
    }

    pub fn get(&self, pns: u32, pid: u32) -> String {
        if let Some(v) = self.cache.get(&pns) {
            return v;
        }
        if self.rlimit.check().is_err() {
            return ERATELIMIT.to_string();
        }
        let file = match read(format!("/proc/{}/environ", pid)) {
            Ok(f) => f,
            Err(_) => return ENOTFOUND.to_string(),
        };
        let mut pod_name = String::new();
        for mut kv in file
            .split(|c| *c == b'\0')
            .map(|s| s.splitn(2, |c| *c == b'='))
        {
            if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                if matches!(k, b"MY_POD_NAME" | b"POD_NAME") {
                    pod_name.push_str(str::from_utf8(v).unwrap_or(""));
                    break;
                }
            }
        }
        if pod_name.is_empty() {
            return pod_name;
        }
        self.cache.insert(pns, pod_name.clone());
        pod_name
    }
}
