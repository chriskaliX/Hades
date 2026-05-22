//! event/ — mirrors Go's collector/event/ package.
//!
//! Top-level entry files (process, user, sshd, cron, cron_watcher, container,
//! configs_runner, libraries_runner) live here directly.
//! Sub-packages (systems/, networks/, configs/, libraries/) are nested sub-modules.

pub mod application;
pub mod apps;
pub mod configs;
pub mod configs_runner;
pub mod container;
pub mod cron;
pub mod cron_watcher;
pub mod libraries;
pub mod libraries_runner;
pub mod networks;
pub mod process;
pub mod sshd;
pub mod systems;
pub mod user;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Per-run unique sequence identifier — mirrors Go's `utils.Hash()`.
pub fn hash() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let v: u64 = (t.as_secs() << 32) ^ t.subsec_nanos() as u64;
    format!("{v:016x}")
}

/// Build a `sdk::Record` from a data_type + field map.
pub fn make_record(data_type: i32, fields: HashMap<String, String>) -> sdk::Record {
    sdk::Record {
        data_type,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
        data: Some(sdk::Payload { fields }),
    }
}

use crate::manager::EventManager;
use std::time::Duration;

/// Register every event with the EventManager — mirrors Go's main.go setup.
pub fn register(em: &mut EventManager) {
    // ── Realtime ────────────────────────────────────────────────────────
    em.add_event(sshd::Sshd::new(),                   Duration::ZERO);
    em.add_event(cron_watcher::CronWatcher::new(),    Duration::ZERO);

    // ── Periodic: short intervals ───────────────────────────────────────
    em.add_event(container::Container,                Duration::from_secs(5  * 60));
    em.add_event(user::User,                          Duration::from_secs(10 * 60));
    em.add_event(process::Process,                    Duration::from_secs(15 * 60));

    // ── Periodic: long intervals ────────────────────────────────────────
    em.add_event(cron::Cron,                          Duration::from_secs(24 * 3600));
    em.add_event(configs_runner::Configs,             Duration::from_secs(6  * 3600));
    em.add_event(libraries_runner::Libraries,         Duration::from_secs(24 * 3600));
    em.add_event(application::Application::new(),     Duration::from_secs(24 * 3600));

    // ── Sub-groups ──────────────────────────────────────────────────────
    systems::register(em);
    networks::register(em);
}
