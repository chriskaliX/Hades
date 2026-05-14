/// User collector — data_type 3004.
/// Parses /etc/passwd + /etc/shadow.  Mirrors Go's event/user.go.
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;

use crate::cache;
use crate::manager::{EventMode, IEvent};
use crate::cache::user::group_name;
use crate::event::{hash, make_record};

const DATA_TYPE: i32 = 3004;
// Seconds-per-day constant for epoch-days → timestamp conversion
const SPD: i64 = 86_400;

pub struct User;

#[async_trait]
impl IEvent for User {
    fn name(&self)        -> &'static str { "user" }
    fn data_type(&self)   -> i32          { DATA_TYPE }
    fn flag(&self)        -> EventMode    { EventMode::Periodic }
    fn immediately(&self) -> bool         { true }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        let shadow  = read_shadow();
        let seq     = hash();

        if let Ok(f) = File::open("/etc/passwd") {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                let parts: Vec<&str> = line.splitn(7, ':').collect();
                if parts.len() < 7 { continue; }
                let (username, uid, gid, info, home_dir, shell) =
                    (parts[0], parts[2], parts[3], parts[4], parts[5], parts[6]);

                let uid_u32: u32 = uid.parse().unwrap_or(0);
                let gid_u32: u32 = gid.parse().unwrap_or(0);
                let sentry  = shadow.get(username).cloned().unwrap_or_default();
                // Pre-warm the user cache so subsequent events (process, application)
                // don't need to re-scan /etc/passwd for this uid.
                cache::user::insert(uid_u32, username.to_owned());

                let mut fields: HashMap<String, String> = HashMap::new();
                fields.insert("username".into(),             username.to_owned());
                fields.insert("uid".into(),                  uid.to_owned());
                fields.insert("gid".into(),                  gid.to_owned());
                fields.insert("group_name".into(),           group_name(gid_u32));
                fields.insert("info".into(),                 info.to_owned());
                fields.insert("home_dir".into(),             home_dir.to_owned());
                fields.insert("shell".into(),                shell.to_owned());
                fields.insert("password".into(),             sentry.first().cloned().unwrap_or_default());
                fields.insert("password_update_time".into(), days_to_date(sentry.get(1)));
                fields.insert("password_change_interval".into(), sentry.get(2).cloned().unwrap_or_default());
                fields.insert("password_validity".into(),    days_to_date(sentry.get(3)));
                fields.insert("password_warn_before_expire".into(), sentry.get(4).cloned().unwrap_or_default());
                fields.insert("password_grace_period".into(), sentry.get(5).cloned().unwrap_or_default());
                fields.insert("last_login_time".into(),      String::new());
                fields.insert("last_login_ip".into(),        String::new());
                fields.insert("package_seq".into(),          seq.clone());
                let _ = client.send_record(&make_record(DATA_TYPE, fields));
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        Ok(())
    }
}

/// Read /etc/shadow → username → [password, lastchange, min, max, warn, inactive]
fn read_shadow() -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    let Ok(f) = File::open("/etc/shadow") else { return map };
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        let parts: Vec<&str> = line.splitn(9, ':').collect();
        if parts.len() >= 7 {
            // index 1=password, 2=lastchange, 3=min, 4=max, 5=warn, 6=inactive
            map.insert(parts[0].to_owned(),
                parts[1..7].iter().map(|s| s.to_string()).collect());
        }
    }
    map
}

/// Convert epoch-days string to "YYYY-MM-DD 00:00:00" or return empty on failure.
fn days_to_date(days_str: Option<&String>) -> String {
    days_to_date_inner(days_str).unwrap_or_default()
}

fn days_to_date_inner(days_str: Option<&String>) -> Option<String> {
    let s = days_str?;
    let days: i64 = s.trim().parse().ok()?;
    if days == 0 { return Some(String::new()); }
    let ts = days * SPD;
    // Format via raw libc gmtime
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        libc::gmtime_r(&ts, &mut tm);
        let year = tm.tm_year + 1900;
        let mon  = tm.tm_mon  + 1;
        let day  = tm.tm_mday;
        Some(format!("{year:04}-{mon:02}-{day:02} 00:00:00"))
    }
}
