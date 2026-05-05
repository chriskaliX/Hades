use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use tokio::io::AsyncReadExt as _;
use tokio::sync::mpsc;

use crate::proto::{
    file_ext_client::FileExtClient,
    FileUploadRequest,
};

const TIMEOUT_SECS: u64 = 600;
const MAX_BUF:      usize = 256 * 1024;
const DEFAULT_BUF:  usize =  64 * 1024;

pub struct UploadRequest {
    pub path:     String,
    pub buf_size: u64,
    pub token:    String,
}

// Sender is stored globally; Receiver ownership is transferred in/out of the
// Mutex only at session boundaries (never held across await points).
static UPLOAD_TX: OnceLock<mpsc::Sender<UploadRequest>> = OnceLock::new();
static UPLOAD_RX: LazyLock<std::sync::Mutex<Option<mpsc::Receiver<UploadRequest>>>> =
    LazyLock::new(|| {
        let (tx, rx) = mpsc::channel(1);
        let _ = UPLOAD_TX.set(tx);
        std::sync::Mutex::new(Some(rx))
    });

pub fn upload_file(req: UploadRequest) -> anyhow::Result<()> {
    UPLOAD_TX
        .get()
        .ok_or_else(|| anyhow::anyhow!("file_ext not initialised"))?
        .try_send(req)
        .map_err(|_| anyhow::anyhow!("last upload task hasn't completed"))
}

pub async fn start_file_ext(token: tokio_util::sync::CancellationToken) {
    log::info!("file_ext handler started");
    // Take receiver ownership out of the static — held in local scope for the
    // session, so recv().await never contends with the std::sync::Mutex.
    let mut rx = UPLOAD_RX.lock().unwrap().take()
        .expect("start_file_ext called concurrently");
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            req = rx.recv() => {
                let Some(req) = req else { break };
                tokio::spawn(async move {
                    if let Err(e) = handle_upload(req).await {
                        log::error!("upload error: {e}");
                    }
                });
            }
        }
    }
    // Return receiver so the next session can reuse the same channel.
    *UPLOAD_RX.lock().unwrap() = Some(rx);
    log::info!("file_ext handler exited");
}

async fn handle_upload(req: UploadRequest) -> anyhow::Result<()> {
    log::info!("uploading {:?}", req.path);

    let rate      = req.buf_size; // bytes/sec; 0 = unlimited
    let file_meta = std::fs::metadata(&req.path)?;
    let file_size = file_meta.len();
    if rate > 0 && file_size > rate * TIMEOUT_SECS {
        let msg = format!("size limit exceeded: ({}/{})", file_size, rate * TIMEOUT_SECS);
        super::transfer::task_error(&req.token, &msg);
        anyhow::bail!(msg);
    }

    let ch = super::connection::get_connection()?;
    let mut client = FileExtClient::new(ch)
        .send_compressed(tonic::codec::CompressionEncoding::Gzip)
        .accept_compressed(tonic::codec::CompressionEncoding::Gzip);

    // Chunk size: one second's worth of data, capped at MAX_BUF.
    // With rate limiting, one chunk per second = exactly `rate` bytes/sec.
    // Same structure as Elkeid Go: one write per ticker tick.
    let buf_size = if rate == 0 { DEFAULT_BUF } else { (rate as usize).min(MAX_BUF) };
    let mut file = tokio::fs::File::open(&req.path).await?;
    let token    = req.token.clone();

    let stream = async_stream::stream! {
        let mut buf  = vec![0u8; buf_size];
        let mut sent = 0u64;
        loop {
            let n = match file.read(&mut buf).await {
                Ok(0) => return,
                Ok(n) => n,
                Err(e) => {
                    super::transfer::task_error(&token, &e.to_string());
                    return;
                }
            };
            sent += n as u64;
            log::info!("upload progress: {}/{}", sent, file_size);
            yield FileUploadRequest { token: token.clone(), data: buf[..n].to_vec() };
            if rate > 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    };

    let response = tokio::time::timeout(
        Duration::from_secs(TIMEOUT_SECS),
        client.upload(stream),
    )
    .await
    .map_err(|_| anyhow::anyhow!("upload timed out"))?
    .map_err(|s| anyhow::anyhow!("upload RPC error: {s}"))?;

    log::info!("upload complete: {:?}", response.into_inner().status);
    Ok(())
}
