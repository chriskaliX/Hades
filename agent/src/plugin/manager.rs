//! Plugin registry. Mirrors Go's `agent/plugin/manager.go`.
//!
//! Stores running plugins by name and exposes the load / unregist /
//! shutdown operations consumed by the dispatch loop. Per-process
//! lifecycle lives in [`super::plugin`].

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result};
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use super::plugin::Plugin;
use crate::metrics::plugin::PluginSnapshot;
use crate::proto::Config;

/// Outcome of [`Manager::load`].
pub(super) enum LoadStatus {
    /// Plugin was (re)started successfully.
    Success,
    /// Plugin start failed; carries the underlying error for the caller to log.
    Fail(anyhow::Error),
    /// Same version already running, nothing to do.
    Skip,
}

/// In-memory registry of running plugins.
#[derive(Default)]
pub(super) struct Manager {
    plugins: Mutex<HashMap<String, Arc<Plugin>>>,
}

impl Manager {
    pub(super) fn get(&self, name: &str) -> Option<Arc<Plugin>> {
        self.plugins.lock().get(name).cloned()
    }

    pub(super) fn names(&self) -> Vec<String> {
        self.plugins.lock().keys().cloned().collect()
    }

    pub(super) fn snapshots(&self) -> Vec<PluginSnapshot> {
        self.plugins
            .lock()
            .values()
            .filter_map(|plugin| plugin.snapshot())
            .collect()
    }

    /// Start (or upgrade) a plugin from a server-pushed [`Config`].
    pub(super) fn load(&self, token: &CancellationToken, mut cfg: Config) -> LoadStatus {
        if let Some(existing) = self.get(&cfg.name) {
            if !existing.is_exited() {
                if existing.version() == cfg.version {
                    return LoadStatus::Skip;
                }
                log::info!(
                    "start to shutdown plugin {}, version {}",
                    existing.name(),
                    existing.version()
                );
                existing.shutdown();
            }
        }

        if cfg.signature.is_empty() {
            cfg.signature = cfg.sha256.clone();
        }

        match Plugin::spawn(token, &cfg) {
            Ok(plugin) => {
                self.plugins.lock().insert(cfg.name.clone(), plugin);
                LoadStatus::Success
            }
            Err(err) => LoadStatus::Fail(err.context(format!("plugin {} starts failed", cfg.name))),
        }
    }

    /// Stop a plugin and remove its working directory.
    ///
    /// Mirrors Go's `unRegist`: shutdown first, verify the process actually
    /// exited, then drop it from the registry and clean up on disk.
    pub(super) fn unregist(&self, name: &str) -> Result<()> {
        let plugin = self
            .get(name)
            .with_context(|| format!("plugin {name} not exists"))?;

        plugin.shutdown();
        if !plugin.is_exited() {
            // shutdown's SIGKILL path should make this unreachable, but keep
            // the workdir intact if somehow the child is still alive so a
            // later retry can clean up.
            anyhow::bail!("plugin {name} still running after shutdown");
        }

        self.plugins.lock().remove(name);
        fs::remove_dir_all(plugin.working_directory())
            .with_context(|| format!("remove {name} work dir failed"))?;
        Ok(())
    }

    pub(super) fn shutdown_all(&self) {
        for name in self.names() {
            if let Err(err) = self.unregist(&name) {
                log::warn!("plugin {name} shutdown failed: {err}");
            }
        }
    }
}
