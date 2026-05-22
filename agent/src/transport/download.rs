//! Shared download + signature-check utilities.
//!
//! Mirrors Go's `agent/utils/download.go` (CheckSignature + Download).

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::path::Path;
use tempfile::NamedTempFile;
use tokio_util::sync::CancellationToken;

pub const MAX_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// Verify the SHA-256 digest of an existing file.
/// Returns `Ok(())` if `sha256sum` is empty (no check required) or matches.
pub fn check_signature(path: &Path, sha256sum: &str) -> Result<()> {
    if sha256sum.is_empty() {
        return Ok(());
    }
    let hash = hex::encode(Sha256::digest(std::fs::read(path)?));
    if !hash.eq_ignore_ascii_case(sha256sum) {
        bail!("signature mismatch");
    }
    Ok(())
}

/// Download `urls` in order until one succeeds.  Verifies SHA-256 after each
/// attempt and extracts tar.gz archives in-place.  Mirrors Go's `utils.Download`.
///
/// `exec_path` is the final destination for the binary (used for non-archive
/// packages and for the post-download existence check).
pub fn download(
    token: &CancellationToken,
    urls: &[String],
    sha256sum: &str,
    pkg_type: &str,
    workdir: &Path,
    exec_path: &Path,
) -> Result<()> {
    if urls.is_empty() {
        bail!("no download URLs provided");
    }
    let mut last_err = anyhow::anyhow!("all download URLs failed");
    for url in urls {
        if token.is_cancelled() {
            bail!("download cancelled");
        }
        match try_download(url, sha256sum, pkg_type, workdir, exec_path) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn try_download(
    url: &str,
    sha256sum: &str,
    pkg_type: &str,
    workdir: &Path,
    exec_path: &Path,
) -> Result<()> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(600)))
        .build()
        .into();
    let resp = agent.get(url).call()?;
    let mut src = resp.into_body().into_reader().take(MAX_DOWNLOAD_BYTES);
    let mut hasher = Sha256::new();
    {
        let mut tee = HashRead { inner: &mut src, hasher: &mut hasher };
        let result = match pkg_type {
            "tar.gz" => tar::Archive::new(flate2::read::GzDecoder::new(&mut tee))
                .unpack(workdir)
                .context("tar.gz extraction failed"),
            _ => {
                let mut tmp = NamedTempFile::new_in(workdir)
                    .context("failed to create temp file")?;
                io::copy(&mut tee, &mut tmp)?;
                tmp.persist(exec_path)
                    .with_context(|| format!("failed to persist to {}", exec_path.display()))
                    .map(|_| ())
            }
        };
        if let Err(e) = result {
            let _ = std::fs::remove_dir_all(workdir);
            return Err(e);
        }
    }
    if !sha256sum.is_empty() {
        let hash = hex::encode(hasher.finalize());
        if !hash.eq_ignore_ascii_case(sha256sum) {
            bail!("sha256 mismatch: expected={sha256sum}, actual={hash}");
        }
    }
    if !exec_path.exists() {
        bail!("plugin executable {} not found after download", exec_path.display());
    }
    Ok(())
}

struct HashRead<'a, R> {
    inner: R,
    hasher: &'a mut Sha256,
}

impl<R: Read> Read for HashRead<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}
