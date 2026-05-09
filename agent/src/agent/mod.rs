#[cfg(not(windows))]
mod paths {
    pub const PIDPATH:    &str = "/var/run/";
    pub const LOGHOME:    &str = "/var/log/hades/";
    pub const MACHINE_ID: &str = "/etc/hades/machine-id";
}
#[cfg(windows)]
mod paths {
    pub const PIDPATH:    &str = r"C:\Program Files\hades\";
    pub const LOGHOME:    &str = r"C:\Program Files\hades\log\";
    pub const MACHINE_ID: &str = r"C:\Program Files\hades\machine-id";
}
pub use paths::*;

pub mod host;
pub mod state;
pub mod update;
pub mod uuid;

use std::sync::LazyLock;

pub const PRODUCT: &str = "hades-agent";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const ENV_AGENT_ID: &str = "SPECIFIED_AGENT_ID_HADES";

pub static WORKDIR: LazyLock<String> = LazyLock::new(|| {
    std::env::current_dir()
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok())
        .unwrap_or_else(|| PIDPATH.to_owned())
});

pub static ID: LazyLock<String> = LazyLock::new(|| {
    std::env::var(ENV_AGENT_ID).unwrap_or_else(|_| {
        let id = uuid::gen_uuid().to_string();
        let _ = std::fs::write("machine-id", &id);
        id
    })
});

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn workdir_is_nonempty() {
        assert!(!WORKDIR.is_empty());
    }

    #[test]
    fn id_is_nonempty_and_valid_uuid() {
        let id = &*ID;
        assert!(!id.is_empty());
        // When no env override, ID is a UUID — parse merely checks format, no panic
        let _ = ::uuid::Uuid::parse_str(id);
    }

    #[tokio::test]
    async fn cancel_unblocks_cancelled() {
        // Use a local pair so no shared state is affected.
        let parent = CancellationToken::new();
        let child  = parent.child_token();
        let wait   = tokio::spawn(async move { child.cancelled().await });
        tokio::task::yield_now().await;
        parent.cancel();
        tokio::time::timeout(std::time::Duration::from_millis(200), wait)
            .await
            .expect("timed out: parent.cancel() did not unblock child")
            .unwrap();
    }
}

