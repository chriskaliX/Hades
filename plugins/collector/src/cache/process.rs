/// cache/process — mirrors Go's collector/cache/process/cache.go.
///
/// moka::sync::Cache: pid → argv (max 2048) and pid → comm (max 4096).
/// Also houses the exe hash cache (sdk::hash::HashCache backed by moka),
/// mirroring Go's SDK/go/utils/hash.

use std::sync::OnceLock;

use moka::sync::Cache;

fn argv_cache() -> &'static Cache<i32, String> {
    static V: OnceLock<Cache<i32, String>> = OnceLock::new();
    V.get_or_init(|| Cache::builder().max_capacity(2048).build())
}

fn comm_cache() -> &'static Cache<i32, String> {
    static V: OnceLock<Cache<i32, String>> = OnceLock::new();
    V.get_or_init(|| Cache::builder().max_capacity(4096).build())
}

/// Get cached argv for pid, or read from /proc/<pid>/cmdline and cache it.
pub fn get_argv(pid: i32) -> String {
    argv_cache().get_with(pid, || read_argv(pid))
}

/// Explicitly cache argv (call after reading cmdline in the process event).
pub fn put_argv(pid: i32, argv: String) {
    argv_cache().insert(pid, argv);
}

/// Get cached comm for pid, or read from /proc/<pid>/comm and cache it.
pub fn get_comm(pid: i32) -> String {
    comm_cache().get_with(pid, || read_comm(pid))
}

fn read_argv(pid: i32) -> String {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| {
            let s = b.iter().map(|&c| if c == 0 { b' ' } else { c }).collect::<Vec<_>>();
            let s = String::from_utf8_lossy(&s).trim().to_owned();
            if s.len() > 8192 { s[..8192].to_owned() } else { s }
        })
        .unwrap_or_default()
}

fn read_comm(pid: i32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

// ── exe hash cache ───────────────────────────────────────────────────
//
// Delegates to sdk::hash::HashCache (moka 4096-cap, 600 s idle TTL,
// mtime+size invalidation, xxhash64), matching Go's SDK/go/utils/hash.

/// Return the cached xxhash64 of an executable, or empty string on error.
pub fn exe_hash(path: &str) -> String {
    static CACHE: OnceLock<sdk::hash::HashCache> = OnceLock::new();
    if path.is_empty() { return String::new(); }
    let result = CACHE.get_or_init(|| sdk::hash::HashCache::new(4096)).get(path.as_bytes());
    if result == b"-3" { return String::new(); }
    String::from_utf8(result).unwrap_or_default()
}
