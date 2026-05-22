//! Agent-side plugin server: process management + length-prefixed pipe I/O.
//!
//! Mirrors Go's `SDK/go/transport/server/server.go`. Works at the byte level
//! so callers (agent) remain responsible for proto serialisation/deserialisation.
//!
//! # Design
//! - `send_task_bytes` is **non-blocking** (rendezvous channel, capacity 0),
//!   matching Go SDK's unbuffered `taskCh + select/default`.
//! - A dedicated write thread owns the pipe write-end; dropping the sender
//!   causes the thread to exit and close the pipe → EOF to child.
//! - A dedicated read thread calls `on_record` for every decoded frame.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::process::Child;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Snapshot of a running plugin's I/O statistics plus identity.
#[derive(Clone, Debug, Default)]
pub struct ServerSnapshot {
    pub name: String,
    pub version: String,
    pub pid: u32,
    pub rx_speed: f64,
    pub tx_speed: f64,
    pub rx_tps: f64,
    pub tx_tps: f64,
}

/// Agent-side handle for one running plugin process.
pub struct Server {
    name: String,
    version: String,
    child: Mutex<Child>,
    /// Dropping this sender closes the channel → task write thread exits.
    task_tx: Mutex<Option<std::sync::mpsc::SyncSender<Vec<u8>>>>,
    exited: AtomicBool,
    stats: IoStats,
}

impl Server {
    /// Attach to an already-spawned `child`.
    ///
    /// - `agent_rx` — read end of the record pipe (child writes here)
    /// - `agent_tx` — write end of the task pipe (child reads from here)
    /// - `on_record` — called from the read thread for each received frame
    pub fn new(
        name: String,
        version: String,
        child: Child,
        agent_rx: File,
        agent_tx: File,
        on_record: impl Fn(Vec<u8>) + Send + 'static,
    ) -> Arc<Self> {
        let (task_tx, task_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(0);
        let server = Arc::new(Self {
            name,
            version,
            child: Mutex::new(child),
            task_tx: Mutex::new(Some(task_tx)),
            exited: AtomicBool::new(false),
            stats: IoStats::default(),
        });
        server.clone().spawn_receive_loop(agent_rx, on_record);
        server.clone().spawn_task_loop(task_rx, agent_tx);
        server
    }

    // ── I/O threads ──────────────────────────────────────────────────────────

    fn spawn_receive_loop(
        self: Arc<Self>,
        rx: File,
        on_record: impl Fn(Vec<u8>) + Send + 'static,
    ) {
        let name = self.name.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::with_capacity(128 * 1024, rx);
            loop {
                let mut len_buf = [0_u8; 4];
                if let Err(err) = reader.read_exact(&mut len_buf) {
                    if err.kind() != std::io::ErrorKind::UnexpectedEof {
                        log::info!("plugin {name} receive exits: {err}");
                    }
                    break;
                }
                let len = u32::from_le_bytes(len_buf) as usize;
                let mut payload = vec![0_u8; len];
                if let Err(err) = reader.read_exact(&mut payload) {
                    log::warn!("plugin {name} receive truncated: {err}");
                    break;
                }
                // Child -> agent pipe: this is plugin upload traffic.
                self.stats.record_tx(len as u64);
                on_record(payload);
            }
        });
    }

    fn spawn_task_loop(
        self: Arc<Self>,
        rx: std::sync::mpsc::Receiver<Vec<u8>>,
        tx: File,
    ) {
        let name = self.name.clone();
        std::thread::spawn(move || {
            let mut writer = BufWriter::with_capacity(128 * 1024, tx);
            while let Ok(payload) = rx.recv() {
                let len = payload.len() as u32;
                if writer.write_all(&len.to_le_bytes()).is_err() { break; }
                if writer.write_all(&payload).is_err() { break; }
                if writer.flush().is_err() { break; }
                // Agent -> child pipe: this is plugin receive traffic (tasks/config).
                self.stats.record_rx((payload.len() + 4) as u64);
            }
            log::info!("plugin {name} task loop exits");
        });
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Push a pre-serialised task frame to the plugin (non-blocking).
    ///
    /// Returns an error immediately if the write thread is busy or gone.
    pub fn send_task_bytes(&self, bytes: Vec<u8>) -> Result<(), anyhow::Error> {
        if self.is_exited() {
            anyhow::bail!("plugin is exited");
        }
        let guard = self.task_tx.lock();
        match guard.as_ref() {
            Some(tx) => tx
                .try_send(bytes)
                .map_err(|e| anyhow::anyhow!("task channel: {e}")),
            None => anyhow::bail!("plugin task channel closed"),
        }
    }

    pub fn is_exited(&self) -> bool {
        if self.exited.load(Ordering::Acquire) {
            return true;
        }
        match self.child.lock().try_wait() {
            Ok(Some(_)) => {
                self.exited.store(true, Ordering::Release);
                true
            }
            Ok(None) => false,
            Err(err) => {
                log::warn!("plugin {} try_wait failed: {err}", self.name);
                false
            }
        }
    }

    /// Close the task pipe, wait up to 30 s, then SIGKILL the process group.
    pub fn shutdown(&self) {
        let _ = self.task_tx.lock().take();
        if self.is_exited() {
            return;
        }
        log::info!("shutdown called for plugin {}", self.name);
        let mut child = self.child.lock();
        let pid = child.id() as i32;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.exited.store(true, Ordering::Release);
                    return;
                }
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Ok(None) => {
                    log::warn!("plugin {} did not exit in time, killing", self.name);
                    unsafe { libc::kill(-pid, libc::SIGKILL); }
                    let _ = child.wait();
                    self.exited.store(true, Ordering::Release);
                    return;
                }
                Err(err) => {
                    log::warn!("plugin {} shutdown wait failed: {err}", self.name);
                    return;
                }
            }
        }
    }

    pub fn name(&self) -> &str { &self.name }
    pub fn version(&self) -> &str { &self.version }
    pub fn pid(&self) -> u32 { self.child.lock().id() }

    pub fn snapshot(&self) -> Option<ServerSnapshot> {
        if self.is_exited() {
            return None;
        }
        let pid = self.child.lock().id();
        let s = self.stats.sample();
        Some(ServerSnapshot {
            name: self.name.clone(),
            version: self.version.clone(),
            pid,
            rx_speed: s.rx_speed,
            tx_speed: s.tx_speed,
            rx_tps: s.rx_tps,
            tx_tps: s.tx_tps,
        })
    }
}

// ── IoStats ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct IoStats {
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    rx_cnt:   AtomicU64,
    tx_cnt:   AtomicU64,
    last:     Mutex<Option<Instant>>,
}

struct IoSample { rx_speed: f64, tx_speed: f64, rx_tps: f64, tx_tps: f64 }

impl IoStats {
    fn record_rx(&self, bytes: u64) {
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.rx_cnt.fetch_add(1, Ordering::Relaxed);
    }
    fn record_tx(&self, bytes: u64) {
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.tx_cnt.fetch_add(1, Ordering::Relaxed);
    }
    fn sample(&self) -> IoSample {
        let now = Instant::now();
        let mut last = self.last.lock();
        let elapsed = last
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(0.0);
        *last = Some(now);
        if elapsed <= 0.0 {
            return IoSample { rx_speed: 0.0, tx_speed: 0.0, rx_tps: 0.0, tx_tps: 0.0 };
        }
        IoSample {
            rx_speed: self.rx_bytes.swap(0, Ordering::Relaxed) as f64 / elapsed,
            tx_speed: self.tx_bytes.swap(0, Ordering::Relaxed) as f64 / elapsed,
            rx_tps:   self.rx_cnt.swap(0, Ordering::Relaxed) as f64 / elapsed,
            tx_tps:   self.tx_cnt.swap(0, Ordering::Relaxed) as f64 / elapsed,
        }
    }
}
