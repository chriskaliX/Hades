//! Plugin daemon: dispatches server-pushed tasks/configs to the manager.
//!
//! Mirrors Go's `agent/plugin/plugin.go` — a single `select` loop that
//! consumes [`Task`] / [`Config`] from transport channels and delegates
//! all bookkeeping to [`manager::Manager`].

mod manager;
#[allow(clippy::module_inception)]
mod plugin;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::metrics::plugin::{self as plugin_metrics, PluginSnapshot};
use crate::proto::{Config, Task};
use crate::transport::transfer::{self, task_error, task_success};

use manager::{LoadStatus, Manager};

const PLUGIN_TASK_BUFFER: usize = 32;
const PLUGIN_CONFIG_BUFFER: usize = 8;

/// Active manager handle exposed to the metrics module via a `fn` pointer.
static METRICS_MANAGER: OnceLock<Arc<Manager>> = OnceLock::new();

pub async fn startup(token: CancellationToken) {
    let (task_tx, mut task_rx) = mpsc::channel(PLUGIN_TASK_BUFFER);
    let (config_tx, mut config_rx) = mpsc::channel(PLUGIN_CONFIG_BUFFER);
    let _ = transfer::PLUGIN_TASK_CHAN.set(task_tx);
    let _ = transfer::PLUGIN_CONFIG_CHAN.set(config_tx);

    let manager = Arc::new(Manager::default());
    let _ = METRICS_MANAGER.set(manager.clone());
    plugin_metrics::register_iter(metric_snapshots);

    log::info!("[daemon] plugin starts");
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            Some(task)    = task_rx.recv()   => handle_task(&manager, task),
            Some(configs) = config_rx.recv() => handle_configs(&manager, &token, configs),
        }
    }
    manager.shutdown_all();
    log::info!("[daemon] plugin exits");
}

/// Forward one [`Task`] to the addressed plugin and report status to server.
fn handle_task(manager: &Arc<Manager>, task: Task) {
    let token = task.token.clone();
    match manager.get(&task.object_name) {
        Some(plugin) => match plugin.send_task(&task) {
            Ok(()) => task_success(&token, ""),
            Err(err) => task_error(&token, &format!("send task to plugin: {err}")),
        },
        None => task_error(&token, &format!("can't find plugin {}", task.object_name)),
    }
}

/// Reconcile the running plugin set with the server-pushed config map.
/// Loads new/upgraded plugins, then unregisters anything that disappeared.
fn handle_configs(
    manager: &Arc<Manager>,
    token: &CancellationToken,
    configs: HashMap<String, Config>,
) {
    for cfg in configs.values() {
        match manager.load(token, cfg.clone()) {
            LoadStatus::Success => {}
            LoadStatus::Skip => log::info!("plugin {} has loaded already", cfg.name),
            LoadStatus::Fail(err) => log::error!("plugin {} load failed: {err}", cfg.name),
        }
    }

    for name in manager.names() {
        if configs.contains_key(&name) {
            continue;
        }
        match manager.unregist(&name) {
            Ok(()) => log::info!("plugin {name} is removed"),
            Err(err) => log::error!("plugin {name} remove failed: {err}"),
        }
    }
}

fn metric_snapshots() -> Vec<PluginSnapshot> {
    METRICS_MANAGER.get().map(|m| m.snapshots()).unwrap_or_default()
}
