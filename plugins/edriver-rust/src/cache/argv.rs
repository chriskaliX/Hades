use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use lru::LruCache;
use std::{fs::read, num::NonZeroU32, num::NonZeroUsize};

pub struct ArgvCache {
    cache: LruCache<u32, String>,
    rlimit: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
}

impl ArgvCache {
    pub fn new(s: usize) -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(s).unwrap()),
            rlimit: RateLimiter::direct(Quota::per_second(NonZeroU32::new(25).unwrap())),
        }
    }

    pub fn get(&mut self, pid: u32) -> String {
        match self.cache.get_mut(&pid) {
            Some(v) => v.to_owned(),
            None => {
                if self.rlimit.check().is_err() {
                    return "-4".to_string();
                }
                let mut file = match read(format!("/proc/{}/cmdline", pid)) {
                    Ok(file) => file,
                    Err(_) => return "-3".to_string(),
                };
                if file.len() > 256 {
                    file.truncate(256);
                }
                for v in file.iter_mut() {
                    if *v == b'\0' {
                        *v = b' ';
                    }
                }
                let offset = file
                    .iter()
                    .rposition(|x| !x.is_ascii_whitespace())
                    .unwrap_or_default();
                file.truncate(offset + 1);
                let cmdline = String::from_utf8(file).unwrap_or_default();
                self.put(pid, cmdline.clone());
                cmdline
            }
        }
    }

    pub fn put(&mut self, key: u32, value: String) {
        self.cache.put(key, value);
    }
}
