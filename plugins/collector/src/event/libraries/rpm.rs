/// RPM library collector — data_type 3015.
/// Calls `rpm -qa` to enumerate installed packages.
/// Mirrors Go's event/libraries/rpm.go.
use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

use anyhow::Result;
use sdk::Client;

use crate::event::{hash, make_record};

const DATA_TYPE: i32 = 3015;

const RPM_FMT: &str =
    "%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SIZE}|%{INSTALLTIME}|%{SOURCERPM}\\n";

pub async fn run(client: &mut Client) -> Result<()> {
    let Ok(out) = Command::new("rpm")
        .args(["-qa", "--queryformat", RPM_FMT])
        .output()
    else { return Ok(()) };

    if !out.status.success() { return Ok(()); }

    let seq = hash();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let cols: Vec<&str> = line.splitn(7, '|').collect();
        if cols.len() < 7 { continue; }
        let mut fields = HashMap::new();
        fields.insert("name".into(),         cols[0].to_owned());
        fields.insert("version".into(),      cols[1].to_owned());
        fields.insert("release".into(),      cols[2].to_owned());
        fields.insert("arch".into(),         cols[3].to_owned());
        fields.insert("size".into(),         cols[4].to_owned());
        fields.insert("install_time".into(), cols[5].to_owned());
        fields.insert("source".into(),       cols[6].to_owned());
        fields.insert("package_seq".into(),  seq.clone());
        let _ = client.send_record(&make_record(DATA_TYPE, fields));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}
