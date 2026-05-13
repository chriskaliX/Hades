/// SshdConfig collector — data_type 3002.
/// Parses /etc/ssh/sshd_config for key security settings.
/// Mirrors Go's event/configs/sshdconfig.go.
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read};

use anyhow::Result;
use sdk::Client;

use crate::event::{hash, make_record};

const DATA_TYPE: i32 = 3002;
const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";

pub async fn run(client: &mut Client) -> Result<()> {
    let mut result: HashMap<String, String> = HashMap::new();
    // Defaults (mirrors Go's pre-filled values)
    result.insert("pubkey_authentication".into(), "yes".into());
    result.insert("passwd_authentication".into(), "no".into());
    result.insert("permit_emptypassword".into(),  "no".into());
    result.insert("permit_rootlogin".into(),      "no".into());
    result.insert("port".into(),                  "22".into());
    result.insert("max_authtries".into(),         "-1".into());

    if let Ok(f) = fs::File::open(SSHD_CONFIG) {
        let reader = BufReader::new(f.take(1024 * 1024));
        for line in reader.lines().flatten() {
            let text = line.trim().to_owned();
            if text.is_empty() || text.starts_with('#') { continue; }
            // Split by any whitespace or '=', skip empty tokens — mirrors Go's strings.FieldsFunc
            let fields: Vec<&str> = text
                .split(|c: char| c.is_whitespace() || c == '=')
                .filter(|s| !s.is_empty())
                .collect();
            if fields.len() != 2 { continue; }
            match fields[0] {
                "PasswordAuthentication" => { result.insert("passwd_authentication".into(), fields[1].to_owned()); }
                "PubkeyAuthentication"   => { result.insert("pubkey_authentication".into(), fields[1].to_owned()); }
                "PermitEmptyPasswords"   => { result.insert("permit_emptypassword".into(),  fields[1].to_owned()); }
                "MaxAuthTries"           => { result.insert("max_auth_tries".into(),         fields[1].to_owned()); }
                "PermitRootLogin"        => { result.insert("permit_rootlogin".into(),        fields[1].to_owned()); }
                "Port"                   => { result.insert("port".into(),                    fields[1].to_owned()); }
                _ => {}
            }
        }
    }

    result.insert("package_seq".into(), hash());
    let _ = client.send_record(&make_record(DATA_TYPE, result));
    Ok(())
}
