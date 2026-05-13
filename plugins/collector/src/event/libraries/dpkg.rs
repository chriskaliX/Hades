/// Dpkg library collector — data_type 3016.
/// Parses /var/lib/dpkg/status.  Mirrors Go's event/libraries/dpkg.go.
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::time::Duration;

use anyhow::Result;
use sdk::Client;

use crate::event::{hash, make_record};

const DATA_TYPE: i32 = 3016;

static DPKG_FILES: &[&str] = &[
    "/var/lib/dpkg/status",
    "/usr/local/var/lib/dpkg/status",
];

pub async fn run(client: &mut Client) -> Result<()> {
    let seq = hash();
    for &path in DPKG_FILES {
        let Ok(f) = fs::File::open(path) else { continue };
        let reader = BufReader::new(f.take(25 * 1024 * 1024));
        let records = parse_dpkg(reader);
        for fields in records {
            let mut f = fields;
            f.insert("package_seq".into(), seq.clone());
            let _ = client.send_record(&make_record(DATA_TYPE, f));
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        // only parse the first file found
        break;
    }
    Ok(())
}

/// Parse dpkg status file into one record per package.
/// Uses paragraph-based parsing: blank line separates packages.
fn parse_dpkg(reader: impl BufRead) -> Vec<HashMap<String, String>> {
    let mut result = Vec::new();
    let mut pkg: HashMap<String, String> = HashMap::new();

    for line in reader.lines().flatten() {
        if line.is_empty() {
            flush_pkg(&mut pkg, &mut result);
            continue;
        }
        // Continuation lines start with whitespace — skip
        if line.starts_with(' ') || line.starts_with('\t') { continue; }
        if let Some((k, v)) = line.split_once(": ") {
            match k {
                "Package"        => { pkg.insert("name".into(),     v.to_owned()); }
                "Version"        => { pkg.insert("version".into(),  v.to_owned()); }
                "Source"         => { pkg.insert("source".into(),   v.to_owned()); }
                "Status"         => { pkg.insert("status".into(),   v.to_owned()); }
                "Architecture"   => { pkg.insert("arch".into(),     v.to_owned()); }
                "Installed-Size" => { pkg.insert("size".into(),     v.to_owned()); }
                "Section"        => { pkg.insert("section".into(),  v.to_owned()); }
                "Priority"       => { pkg.insert("priority".into(), v.to_owned()); }
                _ => {}
            }
        }
    }
    flush_pkg(&mut pkg, &mut result);
    result
}

fn flush_pkg(pkg: &mut HashMap<String, String>, out: &mut Vec<HashMap<String, String>>) {
    if pkg.is_empty() { return; }
    let status = pkg.get("status").cloned().unwrap_or_default();
    if status.contains("installed") {
        out.push(pkg.clone());
    }
    pkg.clear();
}
