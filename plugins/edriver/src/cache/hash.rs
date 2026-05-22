use std::{
    fs::File,
    hash::Hasher,
    io::{ErrorKind, Read},
    num::NonZeroU32,
};

use crate::events::{ENOTFOUND, ERATELIMIT};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use hex::encode;
use moka::sync::Cache;
use twox_hash::XxHash64;

pub struct HashCache {
    cache: Cache<String, String>,
    rlimit: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
}

impl HashCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cache: Cache::new(cap as u64),
            rlimit: RateLimiter::direct(Quota::per_second(NonZeroU32::new(100).unwrap())),
        }
    }

    pub fn get(&self, exe: String) -> String {
        if let Some(v) = self.cache.get(&exe) {
            return v;
        }
        if self.rlimit.check().is_err() {
            return ERATELIMIT.to_string();
        }
        let file = match File::open(&exe) {
            Ok(f) => f,
            Err(_) => return ENOTFOUND.to_string(),
        };
        let meta = match file.metadata() {
            Ok(m) => m,
            Err(_) => return ENOTFOUND.to_string(),
        };
        let mut hasher = XxHash64::default();
        hasher.write_u64(meta.len());
        let mut buf = Vec::with_capacity(32 * 1024);
        if let Err(err) = file.take(32 * 1024).read_to_end(&mut buf) {
            if err.kind() != ErrorKind::UnexpectedEof {
                return ENOTFOUND.to_string();
            }
        }
        hasher.write(&buf);
        let hash = encode(hasher.finish().to_be_bytes());
        self.cache.insert(exe, hash.clone());
        hash
    }
}
