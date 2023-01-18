// hash calculate the hash from file
use std::{
    fs::{File},
    hash::Hasher,
    io::{ErrorKind, Read},
    str,
};
use hex::encode;
use lru_cache::LruCache;
use twox_hash::XxHash64;
use std::time::UNIX_EPOCH;

// Default interval time is 10 mins
const INTERVAL:u64 = 600;

pub struct HashCache {
    cache: LruCache<Vec<u8>, FileInfo>,
    buffer: Vec<u8>,
}

pub struct FileInfo {
    size: u64,
    hash: Vec<u8>,
    modified: u64,
    accessed: u64,
}

impl HashCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cache: LruCache::new(cap),
            buffer: Vec::with_capacity(32 * 1024),
        }
    }
    // get hash with modified time and size check
    pub fn get(&mut self, exe: &[u8]) -> Vec<u8> {
        if exe.len() > 1024 {
            return b"-3".to_vec();
        }
        let mut hasher = XxHash64::default();
        return match self.cache.get_mut(exe) {
            Some(fi) => {
                // updater to 1 sec
                let now = coarsetime::Clock::now_since_epoch().as_secs();
                // access time check
                if now <= fi.accessed + INTERVAL {
                    return fi.hash.clone();
                }
                // if anything goes wrong, keep the invalid "-3" for half INTERVAL time
                // read file
                let file = match str::from_utf8(exe) {
                    Ok(v) => { 
                        match File::open(v) {
                            Ok(t) => { t },
                            Err(_) => { return b"-3".to_vec(); }
                        }
                    }
                    Err(_) => { return b"-3".to_vec(); }
                };
                // modified time & size check
                let metadata = match file.metadata() {
                    Ok(v) => { v }
                    Err(_) => { return b"-3".to_vec(); }
                };
                let modified = match metadata.modified() {
                    Ok(v) => { 
                        match v.duration_since(UNIX_EPOCH) {
                            Ok(t) => { t.as_secs() },
                            Err(_) => { return b"-3".to_vec(); }
                        }
                    }
                    Err(_) => { return b"-3".to_vec(); }
                };
                if modified == fi.modified && metadata.len() == fi.size {
                    fi.accessed = now;
                    return fi.hash.clone();
                }
                // hash check
                hasher.write_u64(metadata.len());
                self.buffer.clear();
                if let Err(err) = file.take(32 * 1024).read_to_end(&mut self.buffer) {
                    if err.kind() != ErrorKind::UnexpectedEof {
                        return b"-3".to_vec();
                    }
                }
                hasher.write(&self.buffer);
                let hash = encode(hasher.finish().to_be_bytes()).into_bytes();
                // update the value
                fi.accessed = now;
                fi.modified = modified;
                fi.size = metadata.len();
                fi.hash = hash.clone();
                return hash;
            },
            None => {
                if let Ok(path) = str::from_utf8(exe) {
                    if let Ok(file) = File::open(path) {
                        if let Ok(metadata) = file.metadata() {
                            let modified = match metadata.modified() {
                                Ok(v) => { 
                                    match v.duration_since(UNIX_EPOCH) {
                                        Ok(t) => { t.as_secs() },
                                        Err(_) => { return b"-3".to_vec(); }
                                    }
                                }
                                Err(_) => { return b"-3".to_vec(); }
                            };
                            hasher.write_u64(metadata.len());
                            self.buffer.clear();
                            if let Err(err) = file.take(32 * 1024).read_to_end(&mut self.buffer) {
                                if err.kind() != ErrorKind::UnexpectedEof {
                                    return b"-3".to_vec();
                                }
                            }
                            hasher.write(&self.buffer);
                            let hash = encode(hasher.finish().to_be_bytes()).into_bytes();
                            let fileinfo = FileInfo {
                                size: metadata.len(),
                                hash: hash.clone(),
                                modified: modified,
                                accessed: coarsetime::Clock::now_since_epoch().as_secs()
                            };
                            self.put(exe.to_vec(), fileinfo);
                            hash
                        } else {
                            return b"-3".to_vec();
                        }
                    } else {
                        return b"-3".to_vec();
                    }
                } else {
                    return b"-3".to_vec();
                }
            }
        };
    }

    pub fn put(&mut self, key: Vec<u8>, value: FileInfo) {
        self.cache.insert(key, value);
    }
    
}

#[cfg(test)]
mod hash_test {
    use super::HashCache;
    use std::str;
    
    #[test]
    fn gethash() {
        let mut hashcache = HashCache::new(1024);
        let result = hashcache.get(b"/tmp/hades_test1.log");
        let result2 = hashcache.get(b"/etc/hosts");
        assert_eq!(result, b"-3".to_vec());
        assert_ne!(result2, b"-3".to_vec());
        println!("1: {:?}, 2: {:?}", str::from_utf8(&result).unwrap(), str::from_utf8(&result2).unwrap());
    }

    // use test::Bencher;
    // #[bench]
    // fn gethash_benchmark(bencher: &mut Bencher) {
    //     let mut hashcache = HashCache::new(1024);
    //     bencher.iter( || {
    //         hashcache.get(b"/tmp/hades_test1.log");
    //         hashcache.get(b"/etc/hosts");
    //     });
    // }
}