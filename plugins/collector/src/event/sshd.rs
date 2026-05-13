/// SSHD log watcher — data_type 3003 (Realtime).
/// Uses libc inotify IN_MODIFY on the auth log file.
/// Mirrors Go's event/sshd.go.
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;
use tokio::sync::mpsc;

use crate::manager::{EventMode, IEvent};
use crate::event::make_record;

const DATA_TYPE: i32 = 3003;

// Candidate auth log paths (checked in order)
static LOG_PATHS: &[&str] = &[
    "/var/log/secure",    // RHEL / Fedora
    "/var/log/auth.log",  // Debian / Ubuntu
];

pub struct Sshd {
    log_path:  &'static str,
    last_size: Arc<AtomicI64>,
    rx:        Option<mpsc::Receiver<()>>,
}

impl Sshd {
    pub fn new() -> Self {
        let log_path = LOG_PATHS.iter()
            .find(|&&p| std::path::Path::new(p).exists())
            .copied()
            .unwrap_or(LOG_PATHS[1]);
        Sshd { log_path, last_size: Arc::new(AtomicI64::new(0)), rx: None }
    }
}

#[async_trait]
impl IEvent for Sshd {
    fn name(&self)        -> &'static str { "sshd" }
    fn data_type(&self)   -> i32          { DATA_TYPE }
    fn flag(&self)        -> EventMode    { EventMode::Realtime }
    fn immediately(&self) -> bool         { false }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        // Spawn inotify watcher thread on first call
        if self.rx.is_none() {
            let (tx, rx) = mpsc::channel::<()>(8);
            let path_str = self.log_path.to_owned();
            std::thread::spawn(move || inotify_watch(path_str, tx));
            self.rx = Some(rx);
        }

        let rx = self.rx.as_mut().unwrap();
        loop {
            // Wait for file modification
            let _ = rx.recv().await;
            let mut f = match File::open(self.log_path) { Ok(f) => f, Err(_) => continue };
            let size = f.seek(SeekFrom::End(0)).unwrap_or(0) as i64;
            let prev = self.last_size.load(Ordering::Relaxed);
            if size <= prev { self.last_size.store(size, Ordering::Relaxed); continue; }

            f.seek(SeekFrom::Start(prev as u64)).ok();
            for line in BufReader::new(&f).lines().flatten() {
                self.last_size.store(size, Ordering::Relaxed);
                if !line.contains("sshd[") { continue; }
                if let Some(fields) = parse_sshd_line(&line) {
                    let _ = client.send_record(&make_record(DATA_TYPE, fields));
                }
            }
            // Drain any additional notifications that arrived while processing
            while rx.try_recv().is_ok() {}
        }
    }
}

/// Watch path with IN_MODIFY; send () on each event.
fn inotify_watch(path: String, tx: mpsc::Sender<()>) {
    unsafe {
        let fd = libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK);
        if fd < 0 { return; }
        let cpath = CString::new(path.as_str()).unwrap();
        if libc::inotify_add_watch(fd, cpath.as_ptr(), libc::IN_MODIFY) < 0 {
            libc::close(fd); return;
        }

        // poll loop
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        loop {
            let r = libc::poll(&mut pfd, 1, 5000);
            if r <= 0 { continue; }
            // drain events
            let mut buf = [0u8; 512];
            while libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) > 0 {}
            if tx.blocking_send(()).is_err() { libc::close(fd); return; }
        }
    }
}

/// Parse a sshd log line into record fields.
/// Supports:
///   - 14-field (normal): "Accepted/Failed password for USER from IP port PORT ..."
///   - 16-field (invalid user): "Failed password for invalid user USER from IP port PORT ..."
fn parse_sshd_line(line: &str) -> Option<HashMap<String, String>> {
    if !line.to_lowercase().contains("password") { return None; }
    let words: Vec<&str> = line.split_whitespace().collect();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default();

    let (reason, username, ip, port) = if words.len() >= 16
        && words.get(8) == Some(&"invalid")
    {
        // Failed password for invalid user USER from IP port PORT ...
        let reason   = words.get(5).copied().unwrap_or("").to_lowercase();
        let username = words.get(10).copied().unwrap_or("").to_owned();
        let ip       = words.get(12).copied().unwrap_or("").to_owned();
        let port     = words.get(14).copied().unwrap_or("0").to_owned();
        (reason, username, ip, port)
    } else if words.len() >= 14 {
        let reason   = words.get(5).copied().unwrap_or("").to_lowercase();
        let username = words.get(8).copied().unwrap_or("").to_owned();
        let ip       = words.get(10).copied().unwrap_or("").to_owned();
        let port     = words.get(12).copied().unwrap_or("0").to_owned();
        (reason, username, ip, port)
    } else {
        return None;
    };

    let mut fields = HashMap::new();
    fields.insert("reason".into(),    reason);
    fields.insert("timestamp".into(), ts);
    fields.insert("username".into(),  username);
    fields.insert("ip".into(),        ip);
    fields.insert("port".into(),      port);
    Some(fields)
}
