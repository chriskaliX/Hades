/// cache/container — mirrors Go's collector/cache/container/container.go.
///
/// moka::sync::Cache(1024): pns (u32) → container metadata.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use moka::sync::Cache;

pub const CONTAINER_ID:      &str = "container_id";
pub const CONTAINER_NAME:    &str = "container_name";
pub const CONTAINER_RUNTIME: &str = "container_runtime";

#[derive(Clone)]
struct ContainerInfo {
    id:      String,
    name:    String,
    runtime: String,
}

fn cache() -> &'static Cache<u32, ContainerInfo> {
    static V: OnceLock<Cache<u32, ContainerInfo>> = OnceLock::new();
    V.get_or_init(|| Cache::builder().max_capacity(1024).build())
}

/// Insert or update container info keyed by pns.
pub fn insert(pns: u32, id: String, name: String, runtime: &str) {
    cache().insert(pns, ContainerInfo { id, name, runtime: runtime.to_owned() });
}

/// Look up container info by pns.
pub fn get(pns: u32) -> Option<HashMap<String, String>> {
    cache().get(&pns).map(|info| {
        let mut m = HashMap::with_capacity(3);
        m.insert(CONTAINER_ID.to_owned(),      info.id.clone());
        m.insert(CONTAINER_NAME.to_owned(),    info.name.clone());
        m.insert(CONTAINER_RUNTIME.to_owned(), info.runtime.clone());
        m
    })
}
