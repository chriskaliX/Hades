/// cache/user — mirrors Go's collector/cache/user/user.go.
///
/// moka::sync::Cache(2048) + TTL 1h: uid → username./// Also provides group_name() lookup from /etc/group.
use std::sync::OnceLock;
use std::time::Duration;

use moka::sync::Cache;

fn cache() -> &'static Cache<u32, String> {
    static V: OnceLock<Cache<u32, String>> = OnceLock::new();
    V.get_or_init(|| {
        Cache::builder()
            .max_capacity(2048)
            .time_to_live(Duration::from_secs(3600))
            .build()
    })
}

/// Pre-populate the cache from an already-parsed username (e.g. after user event parses /etc/passwd).
pub fn insert(uid: u32, username: String) {
    cache().insert(uid, username);
}

/// Look up username for a uid. Reads /etc/passwd on miss, caches the result.
pub fn get_username(uid: u32) -> String {
    cache().get_with(uid, || {
        lookup_from_passwd(uid).unwrap_or_else(|| uid.to_string())
    })
}

fn lookup_from_passwd(uid: u32) -> Option<String> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(7, ':').collect();
        if parts.len() >= 3 && parts[2].trim().parse::<u32>().ok() == Some(uid) {
            return Some(parts[0].to_owned());
        }
    }
    None
}

/// Look up group name from /etc/group by numeric gid.
pub fn group_name(gid: u32) -> String {
    if let Ok(f) = std::fs::File::open("/etc/group") {
        use std::io::BufRead;
        for line in std::io::BufReader::new(f).lines().flatten() {
            let parts: Vec<&str> = line.splitn(4, ':').collect();
            if parts.len() >= 3 && parts[2].trim().parse::<u32>().ok() == Some(gid) {
                return parts[0].to_owned();
            }
        }
    }
    String::new()
}
