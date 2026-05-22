use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use crate::{
    agent,
    proto::{transfer_client::TransferClient, Command, PackagedData},
};
use tonic::codec::CompressionEncoding;

use super::{
    connection, file,
    transfer::{resolve_config, resolve_task, trans},
};

const HEALTHY_SESSION_SECS: u64 = 30;
const MAX_BACKOFF_SECS:      u64 = 120;

pub async fn startup(token: CancellationToken) {
    log::info!("transport starts");
    // One-time jitter to stagger reconnects on server restart.
    tokio::select! {
        _ = token.cancelled()                                         => return,
        _ = tokio::time::sleep(Duration::from_secs(jitter_secs(3))) => {}
    }

    let mut retries: u32 = 0;
    loop {
        let started = std::time::Instant::now();
        tokio::select! {
            _ = token.cancelled()              => return,
            _ = run_session(token.clone())     => {}
        }
        // Guard against the race where both branches are ready simultaneously.
        if token.is_cancelled() { return; }

        let elapsed = started.elapsed().as_secs();
        if elapsed >= HEALTHY_SESSION_SECS {
            retries = 0;
            log::info!("session ended after {elapsed}s, reconnecting");
            continue;
        }
        // Exponential back-off: 3 → 6 → 12 → … → 120 s, plus ±25 % jitter.
        let base  = (3_u64 << retries.min(6)).min(MAX_BACKOFF_SECS);
        let delay = base + jitter_secs(base / 4 + 1);
        log::warn!("short session ({elapsed}s), retry #{retries} in {delay}s");
        retries += 1;
        tokio::select! {
            _ = token.cancelled()                                          => return,
            _ = tokio::time::sleep(Duration::from_secs(delay))            => {}
        }
    }
}

fn jitter_secs(max: u64) -> u64 {
    if max == 0 { return 0; }
    std::time::SystemTime::UNIX_EPOCH.elapsed()
        .map(|d| d.subsec_nanos() as u64 % max)
        .unwrap_or(0)
}

async fn run_session(ct: CancellationToken) {
    let ch = match connection::get_connection() {
        Ok(ch) => ch,
        Err(e) => { log::error!("get_connection: {e}"); return; }
    };

    let mut client = TransferClient::new(ch)
        .send_compressed(CompressionEncoding::Gzip)
        .accept_compressed(CompressionEncoding::Gzip);

    let (out_tx, out_rx) = mpsc::channel::<PackagedData>(8);

    // Pre-load the channel with an initial registration frame so tonic sends
    // it as the first DATA frame while concurrently waiting for response
    // HEADERS.  This mirrors Go's behaviour: the Go gRPC client's Transfer()
    // returns immediately (no header wait), and the first client Send() drives
    // the server's Recv() which in turn causes Go gRPC to flush response
    // HEADERS.  Tonic blocks transfer().await until response HEADERS arrive,
    // so without this the two sides deadlock (each waiting for the other).
    {
        let h = agent::host::get();
        let init = PackagedData {
            records:       vec![],
            payloads:      vec![],
            agent_id:      agent::ID.clone(),
            intranet_ipv4: if h.private_ipv4.is_empty() { vec![] } else { vec![h.private_ipv4.clone()] },
            intranet_ipv6: if h.private_ipv6.is_empty() { vec![] } else { vec![h.private_ipv6.clone()] },
            extranet_ipv4: if h.public_ipv4.is_empty()  { vec![] } else { vec![h.public_ipv4.clone()] },
            extranet_ipv6: if h.public_ipv6.is_empty()  { vec![] } else { vec![h.public_ipv6.clone()] },
            hostname:      h.hostname.clone(),
            version:       agent::VERSION.to_owned(),
            product:       agent::PRODUCT.to_owned(),
        };
        // Channel capacity is 8; this is the first item so try_send always succeeds.
        let _ = out_tx.try_send(init);
    }

    let inbound = match client.transfer(ReceiverStream::new(out_rx)).await {
        Ok(resp) => { log::info!("transport stream established"); resp.into_inner() }
        Err(e)   => { log::error!("failed to open transfer stream: [{:?}] {}", e.code(), e.message()); return; }
    };

    let session     = ct.child_token();
    let send_handle = tokio::spawn(handle_send(out_tx, session.clone()));
    let file_handle = tokio::spawn(file::start_file_ext(session.clone()));

    handle_receive(inbound, session.clone(), ct).await;

    session.cancel();
    let _ = tokio::join!(send_handle, file_handle);
    log::info!("transport session closed");
}

async fn handle_send(tx: mpsc::Sender<PackagedData>, token: CancellationToken) {
    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = ticker.tick() => {
                if !trans().send(&tx).await { break; }
            }
        }
    }
}

async fn handle_receive(mut inbound: tonic::codec::Streaming<Command>, session: CancellationToken, ct: CancellationToken) {
    log::info!("transport receive starts");
    loop {
        tokio::select! {
            _ = session.cancelled() => break,
            result = inbound.message() => match result {
                Ok(Some(cmd)) => {
                    trans().rx_cnt.fetch_add(1, Ordering::Relaxed);
                    {
                        use prost::Message as _;
                        let byte_len = cmd.encoded_len() as u64;
                        crate::transport::connection::stats_handler()
                            .rx_bytes.fetch_add(byte_len, Ordering::Relaxed);
                    }
                    agent::state::set_running();
                    if let Err(e) = resolve_cmd(cmd, &ct).await {
                        log::error!("resolve_cmd: {e}");
                    }
                }
                Ok(None) => { log::info!("stream EOF"); break; }
                Err(e)   => { log::error!("recv error: {e}"); break; }
            }
        }
    }
    log::info!("transport receive exits");
}

async fn resolve_cmd(cmd: Command, ct: &CancellationToken) -> anyhow::Result<()> {
    if let Some(task) = cmd.task {
        resolve_task(task, ct)?;
    }
    if !cmd.configs.is_empty() {
        resolve_config(cmd.configs, ct).await?;
    }
    Ok(())
}

