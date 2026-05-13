/// cache/socket — mirrors Go's collector/cache/socket/socket.go.
///
/// moka::sync::Cache(1024): inode (u32) → Socket.

use std::sync::OnceLock;

use moka::sync::Cache;

#[derive(Clone, Debug, Default)]
pub struct Socket {
    pub local_addr:  String,
    pub local_port:  u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state:       String,
    pub protocol:    String, // "tcp" / "udp"
    pub pid:         i32,
}

fn cache() -> &'static Cache<u32, Socket> {
    static V: OnceLock<Cache<u32, Socket>> = OnceLock::new();
    V.get_or_init(|| Cache::builder().max_capacity(1024).build())
}

pub fn get(inode: u32) -> Option<Socket> {
    cache().get(&inode)
}

pub fn put(inode: u32, s: Socket) {
    cache().insert(inode, s);
}
