//! JAR library collector — data_type 3015.
//! Mirrors Go's event/libraries/jar.go.
//!
//! Iterates Java processes, reads their open .jar file descriptors,
//! optionally opens the zip to detect fatjars and MANIFEST.MF versions,
//! and ships one record per jar.

use std::collections::{HashMap, HashSet};
use std::io::BufRead;
use std::time::Duration;

use anyhow::Result;
use sdk::Client;

use crate::cache;
use crate::cache::pid_ns;
use crate::event::{hash, make_record};

const DATA_TYPE:   i32   = 3015;
const MAX_PROCESS: usize = 10000;

pub async fn run(client: &mut Client) -> Result<()> {
    let seq = hash();
    let root_pns = cache::root_pns();

    let pids = tokio::task::spawn_blocking(collect_java_pids).await??;

    for (pid, comm, argv) in pids {
        tokio::time::sleep(Duration::from_millis(50)).await;

        let pns_str = pid_ns(pid);
        let pns_u32: u32 = pns_str.parse().unwrap_or(0);

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

        let (pod_name, _) = if pns_u32 > 0 {
            cache::namespace::get(pid as u32, pns_u32)
        } else {
            Default::default()
        };

        let _ = comm; // comm is "java", confirmed before inclusion
        let base_fields: HashMap<String, String> = [
            ("pid".to_owned(),            pid.to_string()),
            ("pns".to_owned(),            pns_str),
            ("root_pns".to_owned(),       root_pns.to_string()),
            ("pod_name".to_owned(),       pod_name),
            ("cmdline".to_owned(),        argv),
            ("container_id".to_owned(),   container_id),
            ("container_name".to_owned(), container_name),
            ("package_seq".to_owned(),    seq.clone()),
        ].into_iter().collect();

        // Collect .jar fd paths for this pid (blocking)
        let pid_copy = pid;
        let jar_fds = tokio::task::spawn_blocking(move || collect_jar_fds(pid_copy)).await?;

        let mut seen: HashSet<String> = HashSet::new();

        for fd_path in jar_fds {
            let base = std::path::Path::new(&fd_path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();

            if !seen.insert(base.clone()) {
                continue; // deduplicate by basename
            }

            let (name, mut version) = parse_jar_name(&base);
            let zip_path = format!("/proc/{pid}/root{fd_path}");

            // Open jar as zip to detect fatjars and MANIFEST.MF
            if let Ok(mut archive) = zip::ZipArchive::new(std::io::BufReader::new(
                std::fs::File::open(&zip_path)?
            )) {
                // Pass 1: find META-INF/MANIFEST.MF for version if missing
                if version.is_empty() {
                    if let Ok(mf) = archive.by_name("META-INF/MANIFEST.MF") {
                        for line in std::io::BufReader::new(mf).lines().map_while(Result::ok) {
                            if let Some(rest) = line.strip_prefix("Implementation-Version:") {
                                version = rest.trim().to_owned();
                                break;
                            }
                        }
                    }
                }

                // Pass 2: fatjar — send a record for each inner .jar
                let inner_names: Vec<String> = archive.file_names()
                    .filter(|n| n.ends_with(".jar"))
                    .map(str::to_owned)
                    .collect();

                for inner in inner_names {
                    let (inner_name, inner_ver) = parse_jar_name(
                        std::path::Path::new(&inner)
                            .file_name()
                            .map(|n| n.to_str().unwrap_or(""))
                            .unwrap_or("")
                    );
                    let mut fields = base_fields.clone();
                    fields.insert("name".to_owned(),    inner_name);
                    fields.insert("version".to_owned(), inner_ver);
                    fields.insert("path".to_owned(),    fd_path.clone());
                    let _ = client.send_record(&make_record(DATA_TYPE, fields));
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }

            // Send record for the outer jar itself
            let mut fields = base_fields.clone();
            fields.insert("name".to_owned(),    name);
            fields.insert("version".to_owned(), version);
            fields.insert("path".to_owned(),    fd_path);
            let _ = client.send_record(&make_record(DATA_TYPE, fields));
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
    }
    Ok(())
}

/// Returns (pid, comm, argv) for all processes whose comm == "java".
fn collect_java_pids() -> Result<Vec<(i32, String, String)>> {
    let mut out = Vec::new();
    let proc_dir = std::fs::read_dir("/proc")?;
    let mut count = 0;
    for entry in proc_dir.flatten() {
        if count >= MAX_PROCESS { break; }
        let Ok(pid): std::result::Result<i32, _> = entry.file_name().to_string_lossy().parse() else { continue };
        count += 1;
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_owned())
            .unwrap_or_default();
        if comm != "java" { continue; }
        let argv = std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| b.split(|&c| c == 0).filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>().join(" "))
            .unwrap_or_default();
        out.push((pid, comm, argv));
    }
    Ok(out)
}

/// Returns all open fd paths for `pid` that end with `.jar`.
fn collect_jar_fds(pid: i32) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) {
        for entry in entries.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                let path = target.to_string_lossy().into_owned();
                if path.ends_with(".jar") {
                    out.push(path);
                }
            }
        }
    }
    out
}

/// Parse `"kafka_2.13-3.4.0.jar"` → `("kafka_2.13", "3.4.0")`.
/// Mirrors Go's `parseJarName` using a regex-free character scan.
fn parse_jar_name(jar: &str) -> (String, String) {
    let base = jar.strip_suffix(".jar").unwrap_or(jar);
    // Find last `-\d` occurrence that starts a version segment
    let bytes = base.as_bytes();
    let mut ver_start: Option<usize> = None;
    let mut i = base.len().saturating_sub(1);
    while i > 0 {
        if bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            ver_start = Some(i);
            break;
        }
        i -= 1;
    }
    match ver_start {
        Some(pos) => {
            let name    = base[..pos].to_owned();
            let version = base[pos + 1..].to_owned();
            (name, version)
        }
        None => (base.to_owned(), String::new()),
    }
}
