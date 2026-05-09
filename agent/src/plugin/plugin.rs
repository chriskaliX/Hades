//! Per-plugin process lifecycle: spawn, pipe setup, binary acquisition.
//!
//! The transport layer (I/O threads, shutdown, stats) lives in
//! [`sdk::server::Server`]; this file owns the agent-specific concerns:
//! workdir creation, binary download/signature, process exec, and the
//! `on_record` callback that bridges SDK frames to the agent's transfer buffer.

use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::OwnedFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result};
use prost::Message as _;
use tokio_util::sync::CancellationToken;

use sdk::transport::{Server, ServerSnapshot};

use crate::agent;
use crate::transport::download;
use crate::metrics::plugin::PluginSnapshot;
use crate::proto::{Record, Task};
use crate::transport::transfer::trans;

// ── Plugin ────────────────────────────────────────────────────────────────

/// Agent-side handle: wraps [`sdk::server::Server`] with workdir + binary info.
pub(super) struct Plugin {
    workdir: PathBuf,
    server: Arc<Server>,
}

impl Plugin {
    pub(super) fn spawn(token: &CancellationToken, cfg: &crate::proto::Config) -> Result<Arc<Self>> {
        let workdir = Path::new(&*agent::WORKDIR).join("plugin").join(&cfg.name);
        fs::create_dir_all(&workdir)
            .with_context(|| format!("create workdir {}", workdir.display()))?;

        let exec_path = ensure_plugin_binary(token, cfg, &workdir)?;

        // agent_rx ← child_tx (records); child_rx ← agent_tx (tasks).
        // std::io::pipe() uses pipe2(O_CLOEXEC) internally — no unsafe, no libc.
        let (agent_rx_pipe, child_tx_pipe) = std::io::pipe().context("create rx pipe")?;
        let (child_rx_pipe, agent_tx_pipe) = std::io::pipe().context("create tx pipe")?;

        let stderr_path = workdir.join(format!("{}.stderr", cfg.name));
        let stderr = OpenOptions::new()
            .create(true).write(true).truncate(true)
            .open(&stderr_path)
            .with_context(|| format!("open stderr {}", stderr_path.display()))?;

        let child_rx_fd = child_rx_pipe.as_raw_fd();
        let child_tx_fd = child_tx_pipe.as_raw_fd();

        let agent_rx = std::fs::File::from(OwnedFd::from(agent_rx_pipe));
        let agent_tx = std::fs::File::from(OwnedFd::from(agent_tx_pipe));

        let mut cmd = Command::new(&exec_path);
        cmd.current_dir(&workdir).stderr(stderr);
        if !cfg.detail.is_empty() { cmd.env("DETAIL", &cfg.detail); }

        // SDK expects fd 3 = task input (child reads), fd 4 = record output (child writes).
        // Mirrors Go's ExtraFiles = [child_rx, child_tx].
        // dup2(src, dst) clears O_CLOEXEC when src != dst; when src == dst it is a no-op
        // so fcntl(F_SETFD, 0) must follow unconditionally to clear O_CLOEXEC.
        unsafe {
            cmd.pre_exec(move || {
                let cvt = |ret: libc::c_int| -> std::io::Result<()> {
                    if ret == -1 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
                };
                cvt(libc::dup2(child_rx_fd, 3))?;
                cvt(libc::fcntl(3, libc::F_SETFD, 0))?;
                cvt(libc::dup2(child_tx_fd, 4))?;
                cvt(libc::fcntl(4, libc::F_SETFD, 0))?;
                cvt(libc::setpgid(0, 0))
            });
        }

        let child = cmd.spawn()
            .with_context(|| format!("spawn {}", exec_path.display()))?;
        // Release the child's pipe ends from the parent. Crucially, child_tx_pipe
        // (records write end) must be dropped here: as long as the parent holds it
        // open, agent_rx will never see EOF when the child exits.
        drop(child_rx_pipe);
        drop(child_tx_pipe);

        let name = cfg.name.clone();
        let server = Server::new(
            cfg.name.clone(),
            cfg.version.clone(),
            child,
            agent_rx,
            agent_tx,
            move |bytes: Vec<u8>| {
                match Record::decode(bytes.as_slice()) {
                    Ok(record) => {
                        if let Err(err) = trans().transmission(record, false) {
                            log::warn!("plugin {name} record dropped: {err}");
                        }
                    }
                    Err(err) => log::warn!("plugin {name} record decode failed: {err}"),
                }
            },
        );

        Ok(Arc::new(Self { workdir, server }))
    }

    pub(super) fn name(&self)              -> &str   { self.server.name() }
    pub(super) fn version(&self)           -> &str   { self.server.version() }
    pub(super) fn working_directory(&self) -> &Path  { &self.workdir }
    pub(super) fn is_exited(&self)         -> bool   { self.server.is_exited() }
    pub(super) fn shutdown(&self)                    { self.server.shutdown() }

    pub(super) fn send_task(&self, task: &Task) -> Result<()> {
        self.server.send_task_bytes(task.encode_to_vec())
    }

    pub(super) fn snapshot(&self) -> Option<PluginSnapshot> {
        self.server.snapshot().map(|s: ServerSnapshot| PluginSnapshot {
            name: s.name,
            version: s.version,
            pid: s.pid,
            workdir: self.workdir.display().to_string(),
            rx_speed: s.rx_speed,
            tx_speed: s.tx_speed,
            rx_tps: s.rx_tps,
            tx_tps: s.tx_tps,
        })
    }
}

// ── Binary acquisition ─────────────────────────────────────────────────────

fn ensure_plugin_binary(
    token: &CancellationToken,
    cfg: &crate::proto::Config,
    workdir: &Path,
) -> Result<PathBuf> {
    let exec_path = workdir.join(&cfg.name);
    let signature = if cfg.signature.is_empty() { &cfg.sha256 } else { &cfg.signature };
    if !exec_path.exists() || download::check_signature(&exec_path, signature).is_err() {
        download::download(token, &cfg.download_urls, &cfg.sha256, &cfg.r#type, workdir, &exec_path)?;
    }
    let mut perms = fs::metadata(&exec_path)?.permissions();
    perms.set_mode(0o701);
    fs::set_permissions(&exec_path, perms)?;
    Ok(exec_path)
}


