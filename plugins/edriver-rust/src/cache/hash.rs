use std::{
    fs::File,
    hash::Hasher,
    io::{ErrorKind, Read},
    num::{NonZeroU32, NonZeroUsize},
};

use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use hex::encode;
use lru::LruCache;
use twox_hash::XxHash64;

pub struct HashCache {
    cache: LruCache<String, String>,
    buffer: Vec<u8>,
    /* notice: remove the limit if the hash is highly required */
    rlimit: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
}

impl HashCache {
    pub fn new(s: usize) -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(s).unwrap()),
            buffer: Vec::with_capacity(32 * 1024),
            rlimit: RateLimiter::direct(Quota::per_second(NonZeroU32::new(100).unwrap())),
        }
    }

    /* is this gonna bypass the whitelist of exe_hash */
    pub fn get(&mut self, exe: String) -> String {
        let mut hasher = XxHash64::default();
        match self.cache.get_mut(&exe) {
            Some(v) => v.to_owned(),
            None => {
                if self.rlimit.check().is_err() {
                    return "-4".to_string();
                }
                let file = match File::open(exe.clone()) {
                    Ok(file) => file,
                    Err(_) => return "-3".to_string(),
                };
                let meta = match file.metadata() {
                    Ok(file) => file,
                    Err(_) => return "-3".to_string(),
                };
                hasher.write_u64(meta.len());
                self.buffer.clear();
                if let Err(err) = file.take(32 * 1024).read_to_end(&mut self.buffer) {
                    if err.kind() != ErrorKind::UnexpectedEof {
                        return "-3".to_string();
                    }
                }
                hasher.write(&self.buffer);
                let hash = encode(hasher.finish().to_be_bytes());
                self.put(exe, hash.clone());
                hash
            }
        }
    }

    pub fn put(&mut self, key: String, value: String) {
        self.cache.put(key, value);
    }
}
