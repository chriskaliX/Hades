/// Cron collector — data_type 2001.
/// Mirrors Go's event/cron.go.  Reusable parse() function is also consumed by
/// cron_watcher.rs.
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;

use crate::manager::{EventMode, IEvent};
use crate::event::{hash, make_record};

const DATA_TYPE: i32 = 2001;

pub static CRON_DIRS: &[&str] = &[
    "/etc/cron.d",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
];
pub const ETC_CRONTAB: &str = "/etc/crontab";

pub struct Cron;

#[async_trait]
impl IEvent for Cron {
    fn name(&self)        -> &'static str { "cron" }
    fn data_type(&self)   -> i32          { DATA_TYPE }
    fn flag(&self)        -> EventMode    { EventMode::Periodic }
    fn immediately(&self) -> bool         { false }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        let seq = hash();
        // Collect all cron files
        let mut files: Vec<(String, bool)> = Vec::new(); // (path, with_user)

        // /etc/crontab — has user field
        files.push((ETC_CRONTAB.to_owned(), true));

        for dir in CRON_DIRS {
            let with_user = dir.starts_with("/var/spool/cron");
            if let Ok(rd) = fs::read_dir(dir) {
                for entry in rd.flatten() {
                    let path = entry.path().to_string_lossy().to_string();
                    files.push((path, with_user));
                }
            }
        }

        for (path, with_user) in files {
            let Ok(content) = fs::read_to_string(&path) else { continue };
            let entries = parse(with_user, &path, &content);
            for mut fields in entries {
                fields.insert("package_seq".into(), seq.clone());
                let _ = client.send_record(&make_record(DATA_TYPE, fields.clone()));
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        Ok(())
    }
}

// ── Public parse helper (shared with cron_watcher) ──────────────────────────

pub struct CronEntry {
    pub fields: HashMap<String, String>,
}

/// Parse a crontab file.  `with_user=true` means the 6th field is the username
/// (as in /etc/crontab and /etc/cron.d/ files).
pub fn parse(with_user: bool, path: &str, content: &str) -> Vec<HashMap<String, String>> {
    let mut result = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }

        let mut m: HashMap<String, String> = HashMap::new();
        m.insert("path".into(), path.to_owned());

        if let Some(rest) = line.strip_prefix('@') {
            // @reboot / @hourly / etc.
            let (keyword, command) = rest.split_once(char::is_whitespace)
                .unwrap_or((rest, ""));
            m.insert("minute".into(),       format!("@{keyword}"));
            m.insert("hour".into(),         String::new());
            m.insert("day_of_month".into(), String::new());
            m.insert("month".into(),        String::new());
            m.insert("day_of_week".into(),  String::new());
            if with_user {
                let (user, cmd) = command.split_once(char::is_whitespace).unwrap_or(("", command));
                m.insert("user".into(),    user.to_owned());
                m.insert("command".into(), cmd.to_owned());
            } else {
                m.insert("user".into(),    String::new());
                m.insert("command".into(), command.to_owned());
            }
            result.push(m);
            continue;
        }

        let cols: Vec<&str> = line.splitn(7, char::is_whitespace)
            .filter(|s| !s.is_empty())
            .collect();

        if with_user && cols.len() >= 7 {
            m.insert("minute".into(),       cols[0].to_owned());
            m.insert("hour".into(),         cols[1].to_owned());
            m.insert("day_of_month".into(), cols[2].to_owned());
            m.insert("month".into(),        cols[3].to_owned());
            m.insert("day_of_week".into(),  cols[4].to_owned());
            m.insert("user".into(),         cols[5].to_owned());
            m.insert("command".into(),      cols[6..].join(" "));
        } else if !with_user && cols.len() >= 6 {
            m.insert("minute".into(),       cols[0].to_owned());
            m.insert("hour".into(),         cols[1].to_owned());
            m.insert("day_of_month".into(), cols[2].to_owned());
            m.insert("month".into(),        cols[3].to_owned());
            m.insert("day_of_week".into(),  cols[4].to_owned());
            m.insert("user".into(),         String::new());
            m.insert("command".into(),      cols[5..].join(" "));
        } else {
            continue;
        }
        result.push(m);
    }
    result
}
