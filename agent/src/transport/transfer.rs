use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        LazyLock, OnceLock,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::{
    agent,
    proto::{Config, PackagedData, Payload, Record, Task, TaskType},
};
use tokio_util::sync::CancellationToken;

pub const BUFFER_TOTAL:  usize = 8192;
pub const BUFFER_NORMAL: usize = 8186;

pub static PLUGIN_TASK_CHAN:   OnceLock<mpsc::Sender<Task>>                    = OnceLock::new();
pub static PLUGIN_CONFIG_CHAN: OnceLock<mpsc::Sender<HashMap<String, Config>>> = OnceLock::new();

static TRANS: LazyLock<Transfer> = LazyLock::new(Transfer::new);

/// Returns a reference to the process-global [`Transfer`] instance.
pub fn trans() -> &'static Transfer { &TRANS }

pub struct Transfer {
    pub(super) inner:       Mutex<Vec<Record>>,
    pub        tx_cnt:      AtomicU64,
    pub        rx_cnt:      AtomicU64,
    /// Records dropped due to buffer overflow.
    pub        drop_cnt:    AtomicU64,
                            update_time: Mutex<Instant>,
}

impl Transfer {
    pub(super) fn new() -> Self {
        Self {
            inner:       Mutex::new(Vec::with_capacity(BUFFER_TOTAL)),
            tx_cnt:      AtomicU64::new(0),
            rx_cnt:      AtomicU64::new(0),
            drop_cnt:    AtomicU64::new(0),
            update_time: Mutex::new(Instant::now()),
        }
    }

    pub fn transmission(&self, rec: Record, important: bool) -> anyhow::Result<()> {
        let mut buf = self.inner.lock();
        if buf.len() >= BUFFER_NORMAL {
            if important && buf.len() < BUFFER_TOTAL {
                buf.push(rec);
                return Ok(());
            }
            self.drop_cnt.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("buffer overflow");
        }
        buf.push(rec);
        Ok(())
    }

    /// Swap the internal buffer with `out` (which must be empty and pre-allocated).
    /// After the call `out` holds all buffered records; the internal buffer
    /// reclaims `out`'s allocation so producers never block on a re-alloc.
    pub fn drain_into(&self, out: &mut Vec<Record>) {
        debug_assert!(out.is_empty());
        let mut buf = self.inner.lock();
        std::mem::swap(&mut *buf, out);
    }

    /// Atomically drain the record buffer and send one [`PackagedData`] frame.
    ///
    /// Mirrors Go's `Transfer.Send(client)`: lock → drain → unlock → build → send.
    /// Returns `false` if the channel is closed (session should terminate),
    /// `true` in all other cases (including when the buffer was empty).
    pub async fn send(&self, tx: &mpsc::Sender<PackagedData>) -> bool {
        let mut records = Vec::new();
        self.drain_into(&mut records);
        if records.is_empty() { return true; }
        let count = records.len() as u64;
        let h = agent::host::get();
        let msg = PackagedData {
            records,
            payloads:      vec![],
            agent_id:      agent::ID.clone(),
            intranet_ipv4: nonempty_vec(&h.private_ipv4),
            intranet_ipv6: nonempty_vec(&h.private_ipv6),
            extranet_ipv4: nonempty_vec(&h.public_ipv4),
            extranet_ipv6: nonempty_vec(&h.public_ipv6),
            hostname:      h.hostname.clone(),
            version:       agent::VERSION.to_owned(),
            product:       agent::PRODUCT.to_owned(),
        };
        if tx.send(msg).await.is_err() { return false; }
        self.tx_cnt.fetch_add(count, Ordering::Relaxed);
        true
    }

    pub fn get_state(&self) -> (f64, f64) {
        let now  = Instant::now();
        let mut ut = self.update_time.lock();
        let secs = now.duration_since(*ut).as_secs_f64();
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
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
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
