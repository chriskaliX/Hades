use parking_lot::RwLock;
use std::sync::{Arc, LazyLock};

#[derive(Default, Clone)]
pub struct HostInfo {
    pub hostname:     String,
    pub private_ipv4: String,
    pub public_ipv4:  String,
    pub private_ipv6: String,
    pub public_ipv6:  String,
}

static HOST: LazyLock<RwLock<Arc<HostInfo>>> =
    LazyLock::new(|| RwLock::new(Arc::new(HostInfo::default())));

/// Returns a point-in-time snapshot. Lock is held only for `Arc::clone`.
pub fn get() -> Arc<HostInfo> {
    Arc::clone(&HOST.read())
}

/// Replaces the current host info atomically.
pub fn set(info: HostInfo) {
    *HOST.write() = Arc::new(info);
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn set_and_get_roundtrip() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set(HostInfo { hostname: "test-host".to_string(), private_ipv4: "10.0.0.1".to_string(), ..Default::default() });
        let info = get();
        assert_eq!(info.hostname, "test-host");
        assert_eq!(info.private_ipv4, "10.0.0.1");
    }

    #[test]
    fn set_replaces_previous() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set(HostInfo { hostname: "old".to_string(), ..Default::default() });
        set(HostInfo { hostname: "new".to_string(), ..Default::default() });
        assert_eq!(get().hostname, "new");
    }

    #[test]
    fn multiple_gets_see_same_snapshot() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set(HostInfo { public_ipv4: "8.8.8.8".to_string(), ..Default::default() });
        assert_eq!(get().public_ipv4, get().public_ipv4);
    }
}

