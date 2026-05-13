/// cache/namespace — mirrors Go's collector/cache/namespace/ns.go.
///
/// Single moka::sync::Cache<u32, (Option<pod>, Option<node>)>(4096):
/// - None = not resolved yet (TTL_MISS 5min, will retry)
/// - Some(_) = resolved (TTL 1h)

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use moka::Expiry;
use moka::sync::Cache;

const CACHE_SIZE: u64     = 4096;
const TTL:        Duration = Duration::from_secs(3600);
const TTL_MISS:   Duration = Duration::from_secs(300);

type PodNode = (Option<String>, Option<String>);

struct NsExpiry;
impl Expiry<u32, PodNode> for NsExpiry {
    fn expire_after_create(
        &self, _: &u32, (pod, node): &PodNode, _: Instant,
    ) -> Option<Duration> {
        Some(if pod.is_some() && node.is_some() { TTL } else { TTL_MISS })
    }
}

fn ns_cache() -> &'static Cache<u32, PodNode> {
    static V: OnceLock<Cache<u32, PodNode>> = OnceLock::new();
    V.get_or_init(|| {
        Cache::builder()
            .max_capacity(CACHE_SIZE)
            .expire_after(NsExpiry)
            .build()
    })
}

fn hostname() -> &'static str {
    static V: OnceLock<String> = OnceLock::new();
    V.get_or_init(|| {
        std::fs::read_to_string("/etc/hostname")
            .unwrap_or_default()
            .trim()
            .to_owned()
    })
}

/// Look up (pod_name, node_name) for a (pid, pns) pair.
/// Returns empty strings when not found.
pub fn get(pid: u32, pns: u32) -> (String, String) {
    let root_pns = super::root_pns();

    // Fast path: both fields cached and resolved
    if let Some((Some(pod), Some(node))) = ns_cache().get(&pns) {
        return (pod, node);
    }

    // Slow path: read /proc/<pid>/environ
    let mut found_pod: Option<String>  = None;
    let mut found_node: Option<String> = if pns == root_pns {
        Some(hostname().to_owned())
    } else {
        None
    };

    if let Ok(raw) = std::fs::read(format!("/proc/{pid}/environ")) {
        for kv in raw.split(|&b| b == 0) {
            let mut parts = kv.splitn(2, |&b| b == b'=');
            let key   = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default();
            match key {
                b"MY_POD_NAME" | b"POD_NAME" => {
                    found_pod = Some(String::from_utf8_lossy(value).into_owned());
                }
                b"HOSTNAME" if found_node.is_none() => {
                    found_node = Some(String::from_utf8_lossy(value).into_owned());
                }
                _ => {}
            }
            if found_pod.is_some() && found_node.is_some() { break; }
        }
    }

    // as_deref avoids clone: &str → to_owned only when Some
    let pod_out  = found_pod.as_deref().unwrap_or("").to_owned();
    let node_out = found_node.as_deref().unwrap_or("").to_owned();
    // Move found_pod/found_node into cache (no extra clone)
    ns_cache().insert(pns, (found_pod, found_node));
    (pod_out, node_out)
}
