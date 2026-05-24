use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, LazyLock, OnceLock,
    },
};

use coarsetime::{Clock, Instant};

use parking_lot::Mutex;
use prost::Message as _;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::{
    agent,
    proto::{Config, PackagedData, Payload, Record, Task, TaskType},
};
use tokio_util::sync::CancellationToken;

pub const BUFFER_TOTAL:  usize = 8192;
pub const BUFFER_NORMAL: usize = 8160;

pub static PLUGIN_TASK_CHAN:   OnceLock<mpsc::Sender<Task>>                    = OnceLock::new();
pub static PLUGIN_CONFIG_CHAN: OnceLock<mpsc::Sender<HashMap<String, Config>>> = OnceLock::new();

static TRANS: LazyLock<Transfer> = LazyLock::new(Transfer::new);

/// Returns a reference to the process-global [`Transfer`] instance.
pub fn trans() -> &'static Transfer { &TRANS }

/// Pre-built, non-records portion of a [`PackagedData`] frame.
/// Rebuilt only when `agent::host()` issues a new [`Arc`] (IP/hostname change).
struct HdrCache {
    snapshot:      Arc<crate::agent::host::HostInfo>,
    agent_id:      String,
    version:       String,
    product:       String,
    hostname:      String,
    intranet_ipv4: Vec<String>,
    intranet_ipv6: Vec<String>,
    extranet_ipv4: Vec<String>,
    extranet_ipv6: Vec<String>,
}

impl HdrCache {
    fn build(h: Arc<crate::agent::host::HostInfo>) -> Self {
        Self {
            agent_id:      agent::ID.clone(),
            version:       agent::VERSION.to_owned(),
            product:       agent::PRODUCT.to_owned(),
            hostname:      h.hostname.clone(),
            intranet_ipv4: nonempty_vec(&h.private_ipv4),
            intranet_ipv6: nonempty_vec(&h.private_ipv6),
            extranet_ipv4: nonempty_vec(&h.public_ipv4),
            extranet_ipv6: nonempty_vec(&h.public_ipv6),
            snapshot:      h,
        }
    }
}

pub struct Transfer {
    pub(super) inner:       Mutex<Vec<Record>>,
    pub        tx_cnt:      AtomicU64,
    pub        rx_cnt:      AtomicU64,
    /// Records dropped due to buffer overflow.
    pub        drop_cnt:    AtomicU64,
    /// Approximate buffer occupancy; allows a fast idle-skip without locking.
    pub        len_hint:    AtomicUsize,
               update_time: Mutex<Instant>,
    /// Cached PackagedData header; rebuilt only on host-info change.
               hdr:         Mutex<HdrCache>,
}

impl Transfer {
    pub(super) fn new() -> Self {
        Self {
            inner:       Mutex::new(Vec::with_capacity(BUFFER_TOTAL)),
            tx_cnt:      AtomicU64::new(0),
            rx_cnt:      AtomicU64::new(0),
            drop_cnt:    AtomicU64::new(0),
            update_time: Mutex::new(Instant::now()),
            len_hint:    AtomicUsize::new(0),
            hdr:         Mutex::new(HdrCache::build(agent::host::get())),
        }
    }

    pub fn transmission(&self, rec: Record, important: bool) -> anyhow::Result<()> {
        let mut buf = self.inner.lock();
        if buf.len() >= BUFFER_NORMAL {
            if important && buf.len() < BUFFER_TOTAL {
                buf.push(rec);
                self.len_hint.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            self.drop_cnt.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("buffer overflow");
        }
        buf.push(rec);
        self.len_hint.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Swap the internal buffer with `out` (which must be empty and pre-allocated).
    /// After the call `out` holds all buffered records; the internal buffer
    /// reclaims `out`'s allocation so producers never block on a re-alloc.
    pub fn drain_into(&self, out: &mut Vec<Record>) {
        debug_assert!(out.is_empty());
        let mut buf = self.inner.lock();
        std::mem::swap(&mut *buf, out);
        self.len_hint.store(0, Ordering::Relaxed);
    }

    /// Atomically drain the record buffer and send one [`PackagedData`] frame.
    ///
    /// Mirrors Go's `Transfer.Send(client)`: lock → drain → unlock → build → send.
    /// Returns `false` if the channel is closed (session should terminate),
    /// `true` in all other cases (including when the buffer was empty).
    pub async fn send(&self, tx: &mpsc::Sender<PackagedData>) -> bool {
        // Fast path: skip mutex acquisition entirely when nothing is buffered.
        if self.len_hint.load(Ordering::Relaxed) == 0 { return true; }
        let mut records = Vec::new();
        self.drain_into(&mut records);
        if records.is_empty() { return true; }
        let count = records.len() as u64;
        // Use cached header; rebuild only when host info changes (rare).
        let msg = {
            let mut hdr = self.hdr.lock();
            let h = agent::host::get();
            if !Arc::ptr_eq(&h, &hdr.snapshot) {
                *hdr = HdrCache::build(h);
            }
            PackagedData {
                records,
                payloads:      vec![],
                agent_id:      hdr.agent_id.clone(),
                intranet_ipv4: hdr.intranet_ipv4.clone(),
                intranet_ipv6: hdr.intranet_ipv6.clone(),
                extranet_ipv4: hdr.extranet_ipv4.clone(),
                extranet_ipv6: hdr.extranet_ipv6.clone(),
                hostname:      hdr.hostname.clone(),
                version:       hdr.version.clone(),
                product:       hdr.product.clone(),
            }
        };
        let byte_len = msg.encoded_len() as u64;
        if tx.send(msg).await.is_err() { return false; }
        self.tx_cnt.fetch_add(count, Ordering::Relaxed);
        crate::transport::connection::stats_handler()
            .tx_bytes.fetch_add(byte_len, Ordering::Relaxed);
        true
    }

    pub fn get_state(&self) -> (f64, f64) {
        let now = Instant::now();
        let mut ut = self.update_time.lock();
        let secs = (now - *ut).as_f64();
        *ut = now;
        if secs > 0.0 {
            let tx = self.tx_cnt.swap(0, Ordering::Relaxed) as f64 / secs;
            let rx = self.rx_cnt.swap(0, Ordering::Relaxed) as f64 / secs;
            (tx, rx)
        } else {
            (0.0, 0.0)
        }
    }
}

fn nonempty_vec(s: &str) -> Vec<String> {
    (!s.is_empty()).then(|| s.to_owned()).into_iter().collect()
}

fn task_record(token: &str, msg: &str, status: &str) -> Record {
    let ts = Clock::now_since_epoch().as_secs() as i64;
    Record {
        data_type: 5100,
        timestamp: ts,
        data: Some(Payload {
            fields: HashMap::from([
                ("token".into(),  token.into()),
                ("msg".into(),    msg.into()),
                ("status".into(), status.into()),
            ]),
        }),
    }
}

pub fn task_success(token: &str, msg: &str) {
    log::info!("task success: {token} {msg}");
    let _ = trans().transmission(task_record(token, msg, "success"), true);
}

pub fn task_error(token: &str, msg: &str) {
    log::error!("task error: {token} {msg}");
    let _ = trans().transmission(task_record(token, msg, "fail"), true);
}

pub fn resolve_task(task: Task, ct: &CancellationToken) -> anyhow::Result<()> {
    if task.object_name == agent::PRODUCT {
        match TaskType::try_from(task.data_type) {
            Ok(TaskType::TaskShutdown) | Ok(TaskType::TaskRestart) => {
                log::info!("agent shutdown/restart requested");
                task_success(&task.token, "agent shutdown is called");
                ct.cancel();
                return Ok(());
            }
            Ok(TaskType::TaskSetenv | TaskType::TaskUnsetenv) => {
                // env ops are forwarded to plugins; fall through.
            }
            Ok(TaskType::TaskUpload) => {
                #[derive(serde::Deserialize)]
                struct UploadPayload { path: String, #[serde(default)] buf_size: u64 }
                match serde_json::from_str::<UploadPayload>(&task.data) {
                    Ok(p) => {
                        let req = super::file::UploadRequest {
                            path:     p.path,
                            buf_size: p.buf_size,
                            token:    task.token.clone(),
                        };
                        if let Err(e) = super::file::upload_file(req) {
                            task_error(&task.token, &e.to_string());
                        }
                    }
                    Err(e) => task_error(&task.token, &format!("upload: bad payload: {e}")),
                }
                return Ok(());
            }
            _ => {
                let msg = format!("agent datatype {} is not supported", task.data_type);
                task_error(&task.token, &msg);
                anyhow::bail!(msg);
            }
        }
    }
    if let Some(sender) = PLUGIN_TASK_CHAN.get() {
        match sender.try_send(task.clone()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => {
                let msg = "plugin task channel is syncing or is cancelled";
                task_error(&task.token, msg);
                anyhow::bail!(msg);
            }
        }
    } else {
        let msg = "plugin task channel is not initialized";
        task_error(&task.token, msg);
        anyhow::bail!(msg);
    }
    Ok(())
}

pub async fn resolve_config(configs: Vec<Config>, ct: &CancellationToken) -> anyhow::Result<()> {
    let mut map: HashMap<String, Config> = configs
        .into_iter()
        .map(|c| (c.name.clone(), c))
        .collect();

    if let Some(cfg) = map.get(agent::PRODUCT) {
        if cfg.version != agent::VERSION {
            log::info!("agent update {} → {}", agent::VERSION, cfg.version);
            let update_cfg = agent::update::UpdateConfig {
                sha256:        cfg.sha256.clone(),
                download_urls: cfg.download_urls.clone(),
                pkg_type:      cfg.r#type.clone(),
            };
            let token_clone = ct.clone();
            let result = tokio::task::spawn_blocking(move || agent::update::update(&token_clone, &update_cfg))
                .await
                .map_err(|e| anyhow::anyhow!("spawn_blocking join: {e}"))?;

            match result {
                Ok(_) => {
                    log::info!("agent update successful");
                    ct.cancel();
                    return Ok(());
                }
                Err(e) => {
                    let msg = format!("agent update failed: {e}");
                    log::error!("{msg}");
                    agent::state::set_abnormal(&msg);
                }
            }
        }
    }

    map.remove(agent::PRODUCT);
    if let Some(sender) = PLUGIN_CONFIG_CHAN.get() {
        match sender.try_send(map) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => {
                anyhow::bail!("plugin config channel is syncing or is cancelled");
            }
        }
    } else if !map.is_empty() {
        anyhow::bail!("plugin config channel is not initialized");
    }
    Ok(())
}
