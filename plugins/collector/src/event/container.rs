/// Container collector — data_type 3018.
/// Queries Docker Engine API via Unix socket without extra HTTP client deps.
/// Mirrors Go's event/container/container.go.
use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::cache;
use crate::manager::{EventMode, IEvent};
use crate::cache::pid_ns;
use crate::event::{hash, make_record};

const DATA_TYPE:   i32 = 3018;
const DOCKER_SOCK: &str = "/var/run/docker.sock";
const MAX_CONTAINERS: usize = 3000;

pub struct Container;

#[async_trait]
impl IEvent for Container {
    fn name(&self)        -> &'static str { "container" }
    fn data_type(&self)   -> i32          { DATA_TYPE }
    fn flag(&self)        -> EventMode    { EventMode::Periodic }
    fn immediately(&self) -> bool         { true }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        if !std::path::Path::new(DOCKER_SOCK).exists() { return Ok(()); }

        let seq = hash();
        // List all containers
        let list_body = docker_get(&format!(
            "/containers/json?all=1&limit={MAX_CONTAINERS}"
        )).await?;

        let containers: serde_json::Value = serde_json::from_str(&list_body)?;
        let arr = match containers.as_array() {
            Some(a) => a.clone(),
            None    => return Ok(()),
        };

        for item in &arr {
            let id = item["Id"].as_str().unwrap_or("").to_owned();
            if id.is_empty() { continue; }

            // Fetch detailed info for PID
            let detail: serde_json::Value = match docker_get(&format!("/containers/{id}/json")).await {
                Ok(b) => serde_json::from_str(&b).unwrap_or(serde_json::Value::Null),
                Err(_) => serde_json::Value::Null,
            };

            let pid = detail.pointer("/State/Pid")
                .and_then(|v| v.as_i64())
                .unwrap_or(0) as i32;

            let names: Vec<String> = item["Names"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
                .unwrap_or_default();

            let labels_json = serde_json::to_string(&item["Labels"]).unwrap_or_default();

            let short_id: String = id.chars().take(12).collect();
            let image_name = item["Image"].as_str().unwrap_or("").to_owned();
            let pns_str = if pid > 0 { pid_ns(pid) } else { String::new() };

            // Populate the container cache (pns → container info) so that other
            // events (e.g. application) can look up container_id / container_name
            // by process namespace — mirrors Go's cache/container.
            if pid > 0 {
                if let Ok(pns_u32) = pns_str.parse::<u32>() {
                    if pns_u32 > 0 {
                        cache::container::insert(pns_u32, short_id.clone(), image_name.clone(), "docker");
                    }
                }
            }

            let mut fields: HashMap<String, String> = HashMap::new();
            fields.insert("id".into(),         short_id);
            fields.insert("names".into(),       names.join(",").trim_start_matches('/').to_owned());
            fields.insert("image_id".into(),    item["ImageID"].as_str().unwrap_or("").to_owned());
            fields.insert("image_name".into(),  image_name);
            fields.insert("created".into(),     item["Created"].as_i64().unwrap_or(0).to_string());
            fields.insert("state".into(),       item["State"].as_str().unwrap_or("").to_owned());
            fields.insert("status".into(),      item["Status"].as_str().unwrap_or("").to_owned());
            fields.insert("labels".into(),      labels_json);
            fields.insert("pid".into(),         pid.to_string());
            fields.insert("pns".into(),         pns_str);
            fields.insert("package_seq".into(), seq.clone());

            let _ = client.send_record(&make_record(DATA_TYPE, fields));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok(())
    }
}

// ── Minimal HTTP/1.0 over Unix socket ────────────────────────────────────────

async fn docker_get(path: &str) -> Result<String> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        UnixStream::connect(DOCKER_SOCK),
    ).await??;

    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    stream.shutdown().await?;

    let mut resp = String::new();
    stream.read_to_string(&mut resp).await?;

    // Strip HTTP headers — body starts after \r\n\r\n
    let body = resp.find("\r\n\r\n")
        .map(|pos| &resp[pos + 4..])
        .unwrap_or(&resp)
        .to_owned();
    Ok(body)
}
