pub mod argv;
pub mod hash;
pub mod ksym;
pub mod module_scan;
pub mod ns;
pub mod user;

use moka::sync::Cache;
use std::time::Duration;

use self::{
    argv::ArgvCache, hash::HashCache, ksym::KsymCache, module_scan::ModuleScanCache, ns::NsCache,
    user::UserCache,
};

pub struct Transformer {
    pub ns_cache: NsCache,
    pub user_cache: UserCache,
    pub argv_cache: ArgvCache,
    pub hash_cache: HashCache,
    pub ksym_cache: KsymCache,
    pub module_scan_cache: ModuleScanCache,
    /// Connect dedup: key = "sip:sport->dip:dport", expires after 30 min
    pub connect_ttl_cache: Cache<String, ()>,
}

impl Transformer {
    pub fn new() -> Self {
        Self {
            ns_cache: NsCache::new(8 * 1024),
            user_cache: UserCache::new(),
            argv_cache: ArgvCache::new(8 * 1024),
            hash_cache: HashCache::new(8 * 1024),
            ksym_cache: KsymCache::new(Duration::from_secs(300)),
            module_scan_cache: ModuleScanCache::new(1024),
            connect_ttl_cache: Cache::builder()
                .max_capacity(8 * 1024)
                .time_to_live(Duration::from_secs(30 * 60))
                .build(),
        }
    }
}
