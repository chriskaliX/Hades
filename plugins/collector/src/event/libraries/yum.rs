/// YUM repo collector — data_type 3006.
/// Mirrors Go's event/libraries/yum.go.
///
/// Reads /etc/yum.repos.d/**/*.repo files, parses [section] blocks,
/// and ships one record per repository section.
/// Only runs on rhel/fedora/suse platforms.

use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;

use anyhow::Result;
use sdk::Client;

use crate::event::{hash, make_record};

const DATA_TYPE:   i32   = 3006;
const YUM_REPOS_DIR: &str = "/etc/yum.repos.d";
const FILE_LIMIT:  usize = 100;
const RECORD_LIMIT: usize = 1000;
const FILE_SIZE_LIMIT: u64 = 1 * 1024 * 1024;

pub async fn run(client: &mut Client) -> Result<()> {
    // Only run on rpm-based distros — mirrors Go's utils.Platform check
    if !is_rpm_platform() {
        return Ok(());
    }

    let seq = hash();
    let files = collect_repo_files(YUM_REPOS_DIR);
    let mut record_count = 0;

    for file in files {
        let content = match std::fs::OpenOptions::new().read(true).open(&file) {
            Ok(mut f) => {
                let mut buf = String::new();
                let mut limited = (&mut f).take(FILE_SIZE_LIMIT);
                limited.read_to_string(&mut buf).ok();
                buf
            }
            Err(_) => continue,
        };

        // Split into sections on lines that start with "["
        // Mirrors Go's regex `\n\[\S+?\]` section-splitting scanner
        for section in split_sections(&content) {
            if record_count >= RECORD_LIMIT { return Ok(()); }

            let mut fields: HashMap<String, String> = HashMap::new();

            for line in section.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
                    continue;
                }
                // Section header like [base]
                if line.starts_with('[') && line.ends_with(']') {
                    fields.insert("section".to_owned(), line[1..line.len()-1].to_owned());
                    continue;
                }
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim();
                    let value = value.trim().to_owned();
                    match key {
                        "name"       => { fields.insert("name".to_owned(),       value); }
                        "baseurl"    => { fields.insert("baseurl".to_owned(),    value); }
                        "enabled"    => { fields.insert("enabled".to_owned(),    value); }
                        "gpgcheck"   => { fields.insert("gpgcheck".to_owned(),   value); }
                        "gpgkey"     => { fields.insert("gpgkey".to_owned(),     value); }
                        "mirrorlist" => { fields.insert("mirrorlist".to_owned(), value); }
                        _ => {}
                    }
                }
            }

            if fields.is_empty() { continue; }
            fields.insert("package_seq".to_owned(), seq.clone());

            let _ = client.send_record(&make_record(DATA_TYPE, fields));
            record_count += 1;
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    }
    Ok(())
}

/// Collect up to FILE_LIMIT .repo files under `dir`.
fn collect_repo_files(dir: &str) -> Vec<String> {
    let mut files = Vec::new();
    fn walk(dir: &str, files: &mut Vec<String>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if files.len() >= FILE_LIMIT { return; }
                let path = entry.path();
                if path.is_dir() {
                    walk(&path.to_string_lossy(), files);
                } else if path.extension().map_or(false, |e| e == "repo") {
                    files.push(path.to_string_lossy().into_owned());
                }
            }
        }
    }
    walk(dir, &mut files);
    files
}

/// Split a .repo file into sections, one per `[header]` block.
/// Each returned string includes the `[header]` line and subsequent key=value lines.
fn split_sections(content: &str) -> Vec<String> {
    let mut sections: Vec<String> = Vec::new();
    let mut current = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if !current.is_empty() {
                sections.push(std::mem::take(&mut current));
            }
        }
        current.push_str(line);
        current.push('\n');
    }
    if !current.is_empty() {
        sections.push(current);
    }
    sections
}

/// Check /etc/os-release for rhel/fedora/suse/centos family.
fn is_rpm_platform() -> bool {
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some(id) = line.strip_prefix("ID=").or_else(|| line.strip_prefix("ID_LIKE=")) {
                let id = id.trim_matches('"').to_lowercase();
                if id.contains("rhel") || id.contains("fedora") || id.contains("centos")
                    || id.contains("suse") || id.contains("rocky") || id.contains("alma")
                {
                    return true;
                }
            }
        }
    }
    // Fallback: check if the repos dir exists and has .repo files
    std::path::Path::new("/etc/yum.repos.d").exists()
}
