// hash — exe file hashing with moka cache.
//
// Algorithm (mirrors Go SDK/go/utils/hash):
//   xxhash64(decimal_size_string ++ first_32KB_of_file)
//
// moka::sync::Cache is Send+Sync internally, so HashCache needs no external
// Mutex. mtime+size are validated on every access for correctness; entries
// idle out after INTERVAL seconds.

use std::{
    fs::File,
    hash::Hasher,
    io::{ErrorKind, Read},
    str,
    time::{Duration, UNIX_EPOCH},
};

use hex::encode;
use moka::sync::Cache;
use twox_hash::XxHash64;

const INTERVAL: u64 = 600; // idle-eviction TTL, seconds

#[derive(Clone)]
struct FileEntry {
    hash:  Vec<u8>, // hex-encoded xxhash64
    mtime: u64,
    size:  u64,
}

pub struct HashCache {
    cache: Cache<Vec<u8>, FileEntry>,
}

impl HashCache {
    pub fn new(cap: usize) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(cap as u64)
                .time_to_idle(Duration::from_secs(INTERVAL))
                .build(),
        }
    }

    /// Return the xxhash64 of `exe` (hex bytes), or `b"-3"` on any error.
    pub fn get(&self, exe: &[u8]) -> Vec<u8> {
        if exe.len() > 1024 {
            return b"-3".to_vec();
        }
        let Ok(path) = str::from_utf8(exe) else { return b"-3".to_vec() };

        // Cache hit — validate mtime+size, return cached hash if unchanged.
        if let Some(entry) = self.cache.get(exe) {
            if let Some((mtime, size)) = file_stat(path) {
                if mtime == entry.mtime && size == entry.size {
                    return entry.hash.clone();
                }
            }
        }

        // Miss or file changed — compute fresh hash and (re-)insert.
        match compute_hash(path) {
            Some((hash, mtime, size)) => {
                self.cache.insert(exe.to_vec(), FileEntry { hash: hash.clone(), mtime, size });
                hash
            }
            None => b"-3".to_vec(),
        }
    }
}

fn file_stat(path: &str) -> Option<(u64, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta.modified().ok()?
        .duration_since(UNIX_EPOCH).ok()?
        .as_secs();
    Some((mtime, meta.len()))
}

/// xxhash64(decimal_size_string ++ first_32KB) — matches Go's genHash().
fn compute_hash(path: &str) -> Option<(Vec<u8>, u64, u64)> {
    let mut file = File::open(path).ok()?;
    let meta     = file.metadata().ok()?;
    let size     = meta.len();
    let mtime    = meta.modified().ok()?
        .duration_since(UNIX_EPOCH).ok()?
        .as_secs();

    let mut buf = vec![0u8; 32 * 1024];
    let n = match file.read(&mut buf) {
        Ok(n) => n,
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => buf.len(),
        Err(_) => return None,
    };

    let mut h = XxHash64::with_seed(0);
    h.write(size.to_string().as_bytes()); // matches Go strconv.FormatInt(size, 10)
    h.write(&buf[..n]);
    Some((encode(h.finish().to_be_bytes()).into_bytes(), mtime, size))
}

#[cfg(test)]
mod hash_test {
    use super::HashCache;
    use std::str;

    #[test]
    fn gethash() {
        let c = HashCache::new(1024);
        let r1 = c.get(b"/tmp/hades_test1.log");
        let r2 = c.get(b"/etc/hosts");
        assert_eq!(r1, b"-3".to_vec());
        assert_ne!(r2, b"-3".to_vec());
        println!("1: {:?}, 2: {:?}",
            str::from_utf8(&r1).unwrap(),
            str::from_utf8(&r2).unwrap());
    }
}
