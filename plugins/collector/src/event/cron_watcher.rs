/// CronWatcher — data_type 3001 (Realtime).
/// Watches cron directories for changes via libc inotify and sends diffs.
/// Mirrors Go's event/cron_watcher.go.
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;
use tokio::sync::mpsc;

use crate::event::cron::{parse, CRON_DIRS, ETC_CRONTAB};
use crate::manager::{EventMode, IEvent};
use crate::event::make_record;

const DATA_TYPE: i32 = 3001;

pub struct CronWatcher {
    seen: HashSet<u64>,
    rx:   Option<mpsc::Receiver<String>>, // changed file path
}

impl CronWatcher {
    pub fn new() -> Self { CronWatcher { seen: HashSet::new(), rx: None } }
}

#[async_trait]
impl IEvent for CronWatcher {
    fn name(&self)        -> &'static str { "cron_watcher" }
    fn data_type(&self)   -> i32          { DATA_TYPE }
    fn flag(&self)        -> EventMode    { EventMode::Realtime }
    fn immediately(&self) -> bool         { false }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        if self.rx.is_none() {
            let (tx, rx) = mpsc::channel::<String>(16);
            std::thread::spawn(move || watch_cron(tx));
            self.rx = Some(rx);
        }

        let rx = self.rx.as_mut().unwrap();
        loop {
            let Some(path) = rx.recv().await else { break };
            let with_user = path.starts_with("/var/spool/cron");
            let Ok(content) = fs::read_to_string(&path) else { continue };
            let entries = parse(with_user, &path, &content);
            for mut fields in entries {
                let hash = cmd_hash(fields.get("command").map(|s| s.as_str()).unwrap_or(""));
                if self.seen.contains(&hash) { continue; }
                self.seen.insert(hash);
                fields.insert("package_seq".into(), crate::event::hash());
                let _ = client.send_record(&make_record(DATA_TYPE, fields));
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        Ok(())
    }
}

fn cmd_hash(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// inotify thread: watch cron dirs + /etc/crontab, send path on IN_CREATE|IN_MODIFY|IN_CLOSE_WRITE
fn watch_cron(tx: mpsc::Sender<String>) {
    unsafe {
        let fd = libc::inotify_init1(libc::IN_CLOEXEC);
        if fd < 0 { return; }

        let flags = libc::IN_CREATE | libc::IN_MODIFY | libc::IN_CLOSE_WRITE;

        // Watch directories
        let mut wd_to_dir: HashMap<i32, String> = HashMap::new();
        for &dir in CRON_DIRS {
            if let Ok(c) = CString::new(dir) {
                let wd = libc::inotify_add_watch(fd, c.as_ptr(), flags);
                if wd >= 0 { wd_to_dir.insert(wd, dir.to_owned()); }
            }
        }
        // Watch /etc/crontab directly
        if let Ok(c) = CString::new(ETC_CRONTAB) {
            libc::inotify_add_watch(fd, c.as_ptr(), libc::IN_MODIFY | libc::IN_CLOSE_WRITE);
        }

        let name_buf_size = 64usize;
        let event_size = std::mem::size_of::<libc::inotify_event>();
        let buf_size   = (event_size + name_buf_size) * 16;
        let mut buf    = vec![0u8; buf_size];

        loop {
            let n = libc::read(fd, buf.as_mut_ptr() as *mut _, buf_size);
            if n <= 0 { std::thread::sleep(Duration::from_millis(500)); continue; }
            let mut offset = 0isize;
            while offset < n as isize {
                let ev = &*(buf.as_ptr().offset(offset) as *const libc::inotify_event);
                let name_ptr = buf.as_ptr().offset(offset + event_size as isize);
                let name_bytes = std::slice::from_raw_parts(name_ptr, ev.len as usize);
                let name = std::ffi::CStr::from_ptr(name_bytes.as_ptr() as *const i8)
                    .to_string_lossy()
                    .to_string();

                // Determine full path
                let path = if let Some(dir) = wd_to_dir.get(&ev.wd) {
                    format!("{dir}/{name}")
                } else {
                    ETC_CRONTAB.to_owned()
                };

                if !path.is_empty() {
                    let _ = tx.blocking_send(path);
                }
                offset += (event_size + ev.len as usize) as isize;
            }
        }
    }
}
