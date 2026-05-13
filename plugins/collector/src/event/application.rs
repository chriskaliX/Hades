/// Application collector — data_type 3008.
///
/// Mirrors Go's event/apps.go.  Iterates up to 3 000 processes, identifies
/// running applications (nginx, mysql, redis, kafka, java, …), extracts
/// versions, and ships one record per detected application instance.

use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;

use crate::cache::{self, boot_time_secs, pid_ns, ticks_per_second};
use crate::event::{apps::{all_apps, proc_listen_addrs, AppProc, IApp, ERR_IGNORE}, hash, make_record};
use crate::manager::{EventMode, IEvent};

const DATA_TYPE:   i32   = 3008;
const MAX_PROCS:   usize = 3000;

// ── IEvent ────────────────────────────────────────────────────────────────────

pub struct Application {
    apps: Vec<Box<dyn IApp>>,
}

impl Application {
    pub fn new() -> Self {
        Application { apps: all_apps() }
    }
}

#[async_trait]
impl IEvent for Application {
    fn name(&self)        -> &'static str { "application" }
    fn data_type(&self)   -> i32          { DATA_TYPE }
    fn flag(&self)        -> EventMode    { EventMode::Periodic }
    fn immediately(&self) -> bool         { false }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        let seq      = hash();
        let root_pns = pid_ns(1);

        // Collect process snapshots in a blocking thread
        let procs = tokio::task::spawn_blocking(collect_procs).await??;

        for p in &procs {
            for app in self.apps.iter_mut() {
                if !app.matches(p) { continue; }

                let fields = match app.run(p) {
                    Ok(f)  => f,
                    Err(e) if e.to_string() == ERR_IGNORE => continue,
                    Err(e) => {
                        log::debug!("[application] {} run error: {}", app.name(), e);
                        continue;
                    }
                };

                let listen_addrs = proc_listen_addrs(p.pid);

                // Software apps are only reported when they have a listening socket
                if app.app_type() == "software" && listen_addrs.is_empty() {
                    continue;
                }

                // Look up container info and pod/node name by pns.
                let pns_u32: u32 = p.pns.parse().unwrap_or(0);
                let (container_id, container_name) = if pns_u32 > 0 {
                    cache::container::get(pns_u32)
                        .map(|info| (
                            info.get(cache::container::CONTAINER_ID).cloned().unwrap_or_default(),
                            info.get(cache::container::CONTAINER_NAME).cloned().unwrap_or_default(),
                        ))
                        .unwrap_or_default()
                } else {
                    Default::default()
                };
                let (pod_name, _node_name) = if pns_u32 > 0 {
                    cache::namespace::get(p.pid as u32, pns_u32)
                } else {
                    Default::default()
                };

                let mut m = fields;
                // Overwrite / fill common fields (mirrors Go's maps.Copy order)
                m.insert("name".into(),         app.name().to_owned());
                m.insert("type".into(),         app.app_type().to_owned());
                m.insert("version".into(),       app.version().to_owned());
                m.insert("pid".into(),           p.pid.to_string());
                m.insert("pgid".into(),          p.pgid.to_string());
                m.insert("pns".into(),           p.pns.clone());
                m.insert("root_pns".into(),      root_pns.clone());
                m.insert("exe".into(),           p.exe.clone());
                m.insert("cwd".into(),           p.cwd.clone());
                m.insert("cmdline".into(),       p.argv.clone());
                m.insert("uid".into(),           p.uid.to_string());
                m.insert("gid".into(),           p.gid.to_string());
                m.insert("username".into(),      p.username.clone());
                m.insert("start_time".into(),    p.start_time.to_string());
                m.insert("listen_addrs".into(),  listen_addrs);
                m.insert("container_id".into(),  container_id);
                m.insert("container_name".into(), container_name);
                m.insert("pod_name".into(),       pod_name);
                m.insert("package_seq".into(),   seq.clone());

                let _ = client.send_record(&make_record(DATA_TYPE, m));
            }
            // 2 ms between processes (matches Go's 2 * ProcessIntervalMillSec)
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        Ok(())
    }
}

// ── Process collection ────────────────────────────────────────────────────────

fn collect_procs() -> Result<Vec<AppProc>> {
    use procfs::process::all_processes;
    let mut out = Vec::with_capacity(256);

    let boot_time_secs = boot_time_secs();
    let ticks_per_sec  = ticks_per_second();

    for entry in all_processes()?.filter_map(|r| r.ok()).take(MAX_PROCS) {
        let pid = entry.pid();
        let mut ap = AppProc {
            pid,
            uid:        0,
            gid:        0,
            pgid:       0,
            exe:        String::new(),
            cwd:        String::new(),
            name:       String::new(),
            argv:       String::new(),
            pns:        pid_ns(pid),
            username:   String::new(),
            start_time: 0,
        };

        if let Ok(stat) = entry.stat() {
            ap.name       = stat.comm.clone();
            ap.pgid       = stat.pgrp;
            ap.start_time = boot_time_secs + stat.starttime / ticks_per_sec;
        }
        if let Ok(status) = entry.status() {
            ap.uid = status.ruid;
            ap.gid = status.rgid;
            ap.username = cache::user::get_username(ap.uid);
        }
        if let Ok(cmdline) = entry.cmdline() {
            ap.argv = cmdline.join(" ");
        }
        if let Ok(exe) = entry.exe() {
            ap.exe = exe.to_string_lossy().into_owned();
        }
        if let Ok(cwd) = entry.cwd() {
            ap.cwd = cwd.to_string_lossy().into_owned();
        }

        out.push(ap);
    }
    Ok(out)
}


