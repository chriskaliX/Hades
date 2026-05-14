/// SshConfig collector — data_type 3005.
/// Parses /etc/ssh/ssh_config + per-user ~/.ssh/config.
/// Mirrors Go's event/configs/sshconfig.go.
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read};

use anyhow::Result;
use sdk::Client;

use crate::event::{hash, make_record};

const DATA_TYPE: i32 = 3005;
const SYSTEM_SSH_CONFIG: &str = "/etc/ssh/ssh_config";
const USER_SSH_CONFIG:   &str = ".ssh/config";

/// One SSH config block (mirrors Go's sshConfig struct).
struct SshConfigBlock {
    uid:      String,
    block:    String,  // "Host xxx" or "Match xxx"
    option:   String,  // JSON of key→value map
    filepath: String,
}

pub async fn run(client: &mut Client) -> Result<()> {
    let hash_val = hash();
    let mut configs: Vec<SshConfigBlock> = Vec::new();

    // Per-user configs (read /etc/passwd for home dirs)
    for (uid, home) in user_homes() {
        let path = format!("{}/{}", home.trim_end_matches('/'), USER_SSH_CONFIG);
        if let Ok(c) = parse_ssh_config(&uid, &path) {
            configs.extend(c);
        }
    }
    // System config (uid "0")
    if let Ok(c) = parse_ssh_config("0", SYSTEM_SSH_CONFIG) {
        configs.extend(c);
    }

    for cfg in configs {
        let mut fields = HashMap::new();
        fields.insert("uid".into(),         cfg.uid);
        fields.insert("block".into(),       cfg.block);
        fields.insert("option".into(),      cfg.option);
        fields.insert("filepath".into(),    cfg.filepath);
        fields.insert("package_seq".into(), hash_val.clone());
        let _ = client.send_record(&make_record(DATA_TYPE, fields));
    }
    Ok(())
}

/// Parse an SSH config file into blocks (Host/Match blocks → options JSON).
fn parse_ssh_config(uid: &str, path: &str) -> Result<Vec<SshConfigBlock>> {
    let f = fs::File::open(path)?;
    let reader = BufReader::new(f.take(16 * 1024));

    let mut blocks: Vec<SshConfigBlock> = Vec::new();
    let mut current_block = String::new();
    let mut current_opts: HashMap<String, String> = HashMap::new();
    let mut first = true;

    let flush = |block: &str, opts: &HashMap<String, String>, filepath: &str, uid: &str, out: &mut Vec<SshConfigBlock>| {
        if block.is_empty() { return; }
        let option = serde_json::to_string(opts).unwrap_or_default();
        out.push(SshConfigBlock {
            uid:      uid.to_owned(),
            block:    block.to_owned(),
            option,
            filepath: filepath.to_owned(),
        });
    };

    for line in reader.lines().map_while(Result::ok) {
        let text = line.trim().to_lowercase();
        if text.is_empty() || text.starts_with('#') { continue; }

        if text.starts_with("host ") || text.starts_with("match ") {
            if first { first = false; }
            else { flush(&current_block, &current_opts, path, uid, &mut blocks); }
            current_block = text.clone();
            current_opts.clear();
        } else {
            // Go priority: space index first, then equals — mirrors ssh_configs.cpp
            let space_idx  = text.find(' ');
            let equals_idx = text.find('=');
            let (k, v) = match (space_idx, equals_idx) {
                (None, None)       => (text.as_str(), ""),
                (None, Some(ei))   => (text[..ei].trim(),  text[ei+1..].trim()),
                (Some(si), None)   => (text[..si].trim(),  text[si+1..].trim()),
                (Some(si), Some(_))=> (text[..si].trim(),  text[si+1..].trim()),
            };
            current_opts.insert(k.to_owned(), v.to_owned());
        }
    }
    flush(&current_block, &current_opts, path, uid, &mut blocks);
    Ok(blocks)
}

/// Read /etc/passwd to get (uid_string, home_dir) pairs.
fn user_homes() -> Vec<(String, String)> {
    let Ok(f) = fs::File::open("/etc/passwd") else { return Vec::new() };
    BufReader::new(f)
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(7, ':').collect();
            if parts.len() >= 6 {
                Some((parts[2].to_owned(), parts[5].to_owned()))
            } else { None }
        })
        .collect()
}
