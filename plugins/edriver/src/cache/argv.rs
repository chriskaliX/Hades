use crate::events::{ENOTFOUND, ERATELIMIT};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use moka::sync::Cache;
use std::{fs::read, num::NonZeroU32};

pub struct ArgvCache {
    cache: Cache<u32, String>,
    rlimit: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
}

impl ArgvCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cache: Cache::new(cap as u64),
            rlimit: RateLimiter::direct(Quota::per_second(NonZeroU32::new(25).unwrap())),
        }
    }

    pub fn get(&self, pid: u32) -> String {
        if let Some(v) = self.cache.get(&pid) {
            return v;
        }
        if self.rlimit.check().is_err() {
            return ERATELIMIT.to_string();
        }
        let mut file = match read(format!("/proc/{}/cmdline", pid)) {
            Ok(f) => f,
            Err(_) => return ENOTFOUND.to_string(),
        };
        if file.len() > 256 {
            file.truncate(256);
        }
        for b in file.iter_mut() {
            if *b == b'\0' {
                *b = b' ';
            }
        }
        let offset = file.iter().rposition(|x| !x.is_ascii_whitespace()).unwrap_or_default();
        file.truncate(offset + 1);
        let cmdline = String::from_utf8(file).unwrap_or_default();
        self.put(pid, cmdline.clone());
        cmdline
    }

    pub fn put(&self, key: u32, value: String) {
        self.cache.insert(key, value);
    }
}
