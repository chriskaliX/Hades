pub mod ns;

use ns::NsCache;

pub struct Transformer {
    pub ns_cache: NsCache,
}

impl Transformer {
    pub fn new() -> Self {
        Self {
            ns_cache: NsCache::new(8 * 1024),
        }
    }
}
