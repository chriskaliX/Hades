use users::{Users, UsersCache};

pub struct UserCache {
    cache: UsersCache,
}

impl UserCache {
    pub fn new() -> Self {
        Self {
            cache: UsersCache::new(),
        }
    }

    pub fn get(&mut self, uid: u32) -> String {
        if let Some(u) = self.cache.get_user_by_uid(uid) {
            u.name().to_string_lossy().to_string()
        } else {
            "-3".to_string()
        }
    }
}
