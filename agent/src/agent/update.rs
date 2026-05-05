use anyhow::{bail, Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tokio_util::sync::CancellationToken;

use crate::transport::download;
use super::PRODUCT;

pub struct UpdateConfig {
    pub sha256: String,
    pub download_urls: Vec<String>,
    pub pkg_type: String,
}

pub fn update(token: &CancellationToken, config: &UpdateConfig) -> Result<()> {
    let dst = format!("/tmp/{}-updater.pkg", PRODUCT);
    let dst_path = Path::new(&dst);
    let workdir = Path::new("/tmp");
    if download::check_signature(dst_path, &config.sha256).is_ok() {
        return install(&dst);
    }
    download::download(
        token,
        &config.download_urls,
        &config.sha256,
        &config.pkg_type,
        workdir,
        dst_path,
    )?;
    install(&dst)
}

fn install(path: &str) -> Result<()> {
    let status = match detect_platform() {
        "debian" => Command::new("dpkg").args(["-i", path]).status()?,
        "rhel" | "fedora" | "suse" => Command::new("rpm").args(["-Uvh", path]).status()?,
        _ => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                .context("failed to chmod")?;
            Command::new(path).status()?
        }
    };
    if !status.success() {
        bail!("installer exited with {}", status);
    }
    Ok(())
}

/// Mirrors Go's `host.PlatformInformation()` from gopsutil.
fn detect_platform() -> &'static str {
    use std::io::BufRead;
    let Ok(f) = std::fs::File::open("/etc/os-release") else {
        return "";
    };
    let (mut id, mut id_like) = (String::new(), String::new());
    for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
        if let Some(v) = line.strip_prefix("ID=") {
            id = v.trim_matches('"').to_owned();
        } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
            id_like = v
                .trim_matches('"')
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_owned();
        }
    }
    let key = if id_like.is_empty() { &id } else { &id_like };
    match key.as_str() {
        k if k.contains("debian") || k.contains("ubuntu") => "debian",
        k if k.contains("rhel") || k.contains("centos") => "rhel",
        k if k.contains("fedora") => "fedora",
        k if k.contains("suse") => "suse",
        _ => "",
    }
}
