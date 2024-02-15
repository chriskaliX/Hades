pub mod argv;
pub mod hash;
pub mod ns;
pub mod user;

use self::{argv::ArgvCache, hash::HashCache, ns::NsCache, user::UserCache};

pub struct Transformer {
    pub ns_cache: NsCache,
    pub user_cache: UserCache,
    pub argv_cache: ArgvCache,
    pub hash_cache: HashCache,
}

impl Transformer {
    pub fn new() -> Self {
        Self {
            ns_cache: NsCache::new(8 * 1024),
            user_cache: UserCache::new(),
            argv_cache: ArgvCache::new(8 * 1024),
            hash_cache: HashCache::new(8 * 1024),
        }
    }
}
