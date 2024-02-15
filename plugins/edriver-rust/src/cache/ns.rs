use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use lru::LruCache;
use std::{fs::read, num::NonZeroU32, num::NonZeroUsize, str};

pub struct NsCache {
    cache: LruCache<u32, String>,
    rlimit: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
}

impl NsCache {
    pub fn new(s: usize) -> Self {
        Self {
            cache: LruCache::new(NonZeroUsize::new(s).unwrap()),
            rlimit: RateLimiter::direct(Quota::per_second(NonZeroU32::new(25).unwrap())),
        }
    }

    pub fn get(&mut self, pns: u32, pid: u32) -> String {
        let pid = pid.to_string();

        match self.cache.get_mut(&pns) {
            Some(v) => v.to_owned(),
            None => {
                /* ratelimit check */
                if self.rlimit.check().is_err() {
                    return "-4".to_string();
                }
                /* file check */
                let file = match read(format!("/proc/{}/environ", pid)) {
                    Ok(file) => file,
                    Err(_) => return "-3".to_string(),
                };

                /* file extract */
                let envs = file.split(|c| *c == b'\0').map(|s| s.split(|c| *c == b'='));

                let mut pod_name = String::new();
                for mut env in envs {
                    if let Some(env_name) = env.next() {
                        if let Some(env_value) = env.next() {
                            match env_name {
                                b"MY_POD_NAME" | b"POD_NAME" => {
                                    pod_name.push_str(str::from_utf8(env_value).unwrap_or(""));
                                }
                                _ => {}
                            }
                        }
                    }
                    if !pod_name.is_empty() {
                        break;
                    }
                }
                /* empty short */
                if pod_name.len() == 0 {
                    return pod_name;
                }
                /* cache the name */
                self.put(pns, pod_name.clone());
                pod_name
            }
        }
    }

    pub fn put(&mut self, key: u32, value: String) {
        self.cache.put(key, value);
    }
}
