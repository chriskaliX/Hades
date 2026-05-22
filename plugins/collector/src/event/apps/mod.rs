//! event/apps — mirrors Go's collector/event/apps package.
//!
//! Provides the IApp trait, AppProc data, execution helpers, and the
//! global app registry returned by `all_apps()`.

pub mod bigdata;
pub mod container;
pub mod database;
pub mod service;
pub mod software;
pub mod web;

use crate::cache;

use std::collections::HashMap;
use std::path::Path;

// ── Public errors ────────────────────────────────────────────────────────────

pub const ERR_IGNORE: &str = "ignore";

// ── AppProc ──────────────────────────────────────────────────────────────────

/// Subset of process state needed by the app-matching engine.
#[derive(Debug, Clone)]
pub struct AppProc {
    pub pid:      i32,
    pub uid:      u32,
    pub gid:      u32,
    pub pgid:     i32,
    pub exe:      String,
    pub cwd:      String,
    /// comm field (basename of exe, ≤15 chars)
    pub name:     String,
    /// full /proc/<pid>/cmdline joined with spaces
    pub argv:     String,
    pub pns:      String,
    pub username: String,
    pub start_time: u64,
}

// ── IApp trait ───────────────────────────────────────────────────────────────

/// Mirrors Go's IApplication interface.
pub trait IApp: Send + Sync {
    fn name(&self)     -> &'static str;
    fn app_type(&self) -> &'static str;
    /// Cached version string populated after `run()`.
    fn version(&self)  -> &str;
    /// Return true if this process matches the application.
    fn matches(&mut self, p: &AppProc) -> bool;
    /// Populate version and return app-specific extra fields.
    fn run(&mut self, p: &AppProc) -> anyhow::Result<HashMap<String, String>>;
}

// ── Registry ─────────────────────────────────────────────────────────────────

/// Construct every registered IApp, ordered so that more-specific apps come
/// before the generic software ones (mirrors Go's Regist priority logic).
pub fn all_apps() -> Vec<Box<dyn IApp>> {
    let mut apps: Vec<Box<dyn IApp>> = Vec::new();

    // Non-software categories first (higher priority)
    for a in web::apps()       { apps.push(a); }
    for a in database::apps()  { apps.push(a); }
    for a in bigdata::apps()   { apps.push(a); }
    for a in container::apps() { apps.push(a); }
    for a in service::apps()   { apps.push(a); }
    // Software last (lowest priority — only if no other matcher claimed it)
    for a in software::apps()  { apps.push(a); }

    apps
}

// ── Execute helpers ──────────────────────────────────────────────────────────

/// Run `p.exe args...` with the process's uid/gid, 30 s timeout.
pub fn execute(p: &AppProc, args: &[&str]) -> anyhow::Result<String> {
    execute_with_name(p, &p.exe, args)
}

/// Run `name args...` with the process's uid/gid, 30 s timeout.
pub fn execute_with_name(p: &AppProc, name: &str, args: &[&str]) -> anyhow::Result<String> {
    use std::os::unix::process::CommandExt;

    let uid  = p.uid;
    let gid  = p.gid;
    let cwd  = p.cwd.clone();
    let name = name.to_owned();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

    let (tx, rx) = std::sync::mpsc::channel::<anyhow::Result<String>>();

    std::thread::spawn(move || {
        let mut cmd = std::process::Command::new(&name);
        cmd.args(&args).current_dir(&cwd).env_clear();
        // Drop privileges to the process owner — mirrors Go's SysProcAttr.Credential
        unsafe {
            cmd.pre_exec(move || {
                libc::setgid(gid as libc::gid_t);
                libc::setuid(uid as libc::uid_t);
                Ok(())
            });
        }
        let result = cmd.output()
            .map(|o| {
                let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
                s.push_str(&String::from_utf8_lossy(&o.stderr));
                s
            })
            .map_err(anyhow::Error::from);
        let _ = tx.send(result);
    });

    rx.recv_timeout(std::time::Duration::from_secs(30))
        .map_err(|_| anyhow::anyhow!("execute timeout"))
        .and_then(|r| r)
}

// ── Version extraction ───────────────────────────────────────────────────────

/// Extract the first `x.y[.z…]` version string from free-form text.
/// No regex crate required — pure character scanning.
pub fn find_version(text: &str) -> String {
    for word in text.split(|c: char| c.is_whitespace() || c == '/' || c == '=') {
        // Advance past any non-digit prefix
        if let Some(start) = word.find(|c: char| c.is_ascii_digit()) {
            let s = &word[start..];
            // Take while digit or dot
            let end = s.find(|c: char| !c.is_ascii_digit() && c != '.')
                       .unwrap_or(s.len());
            let candidate = &s[..end];
            if is_version_like(candidate) {
                return candidate.to_owned();
            }
        }
    }
    String::new()
}

fn is_version_like(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 2
        && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

// ── Listen-address helper ────────────────────────────────────────────────────

/// Collect `"ip:port"` strings for sockets owned by `pid` that are in
/// TCP LISTEN state.  Mirrors Go's `ProcListenAddrs`.
///
/// Uses `cache::socket` (populated by the socket event) first; falls back
/// to reading `/proc/net/tcp{6}` directly when the cache has no entry yet.
pub fn proc_listen_addrs(pid: i32) -> String {
    let inodes = collect_socket_inodes(pid);
    if inodes.is_empty() {
        return String::new();
    }

    let mut addrs = Vec::new();

    // Fast path: socket cache (filled by networks::Socket event each 15 min).
    // mirrors Go: socket.Get(uint32(inode)) && soc.State == "10"
    let mut uncached: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for &inode in &inodes {
        if inode > u32::MAX as u64 { continue; }
        match cache::socket::get(inode as u32) {
            Some(s) if s.state == "LISTEN" => {
                addrs.push(format!("{}:{}", s.local_addr, s.local_port));
            }
            Some(_) => {} // known non-LISTEN
            None    => { uncached.insert(inode); }
        }
    }

    // Slow path: scan /proc/net/tcp{6} only for inodes not yet in cache.
    if !uncached.is_empty() {
        for (path, ipv6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines().skip(1) {
                    let f: Vec<&str> = line.split_whitespace().collect();
                    if f.len() < 10 { continue; }
                    if f[3] != "0A" { continue; } // TCP_LISTEN
                    let inode: u64 = f[9].parse().unwrap_or(0);
                    if !uncached.contains(&inode) { continue; }
                    if let Some(addr) = parse_proc_addr(f[1], ipv6) {
                        addrs.push(addr);
                    }
                }
            }
        }
    }

    addrs.join(",")
}

fn collect_socket_inodes(pid: i32) -> std::collections::HashSet<u64> {
    let mut set = std::collections::HashSet::new();
    let fd_dir = format!("/proc/{}/fd", pid);
    if let Ok(entries) = std::fs::read_dir(&fd_dir) {
        for entry in entries.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                let s = target.to_string_lossy();
                if let Some(rest) = s.strip_prefix("socket:[") {
                    if let Some(inode_str) = rest.strip_suffix(']') {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            set.insert(inode);
                        }
                    }
                }
            }
        }
    }
    set
}

/// Parse a `/proc/net/tcp{6}` address field like `"0100007F:0050"` into
/// `"127.0.0.1:80"`.
fn parse_proc_addr(field: &str, ipv6: bool) -> Option<String> {
    let (ip_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if ipv6 {
        parse_hex_ip6(ip_hex)
    } else {
        parse_hex_ip4(ip_hex)
    };
    Some(format!("{}:{}", ip, port))
}

fn parse_hex_ip4(hex: &str) -> String {
    if hex.len() != 8 { return "0.0.0.0".into(); }
    u32::from_str_radix(hex, 16)
        .map(|v| {
            let b = v.to_le_bytes();
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        })
        .unwrap_or_else(|_| "0.0.0.0".into())
}

fn parse_hex_ip6(hex: &str) -> String {
    if hex.len() != 32 { return "::".into(); }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        if let Ok(v) = u32::from_str_radix(&hex[i * 8..(i + 1) * 8], 16) {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
    }
    let groups: Vec<String> = bytes.chunks(2)
        .map(|g| format!("{:02x}{:02x}", g[0], g[1]))
        .collect();
    groups.join(":")
}

// ── JAR fd helper ────────────────────────────────────────────────────────────

/// Return the base names of all `.jar` files found in `/proc/<pid>/fd`.
pub fn jar_names_for_pid(pid: i32) -> Vec<String> {
    let fd_dir = format!("/proc/{}/fd", pid);
    let mut jars = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&fd_dir) {
        for entry in entries.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                let p = Path::new(&target);
                if p.extension().is_some_and(|e| e == "jar") {
                    if let Some(name) = p.file_name() {
                        jars.push(name.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }
    jars
}
