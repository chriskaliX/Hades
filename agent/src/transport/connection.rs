/// gRPC connection with mTLS and lazy reconnect.
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    LazyLock, Mutex, OnceLock,
};
use std::time::{Duration, Instant};

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

/// Default gRPC server address, baked in at compile time.
///
/// Override at **compile time** by setting the `GRPC_ADDR` environment
/// variable before building:
/// ```sh
/// GRPC_ADDR=https://your-server:8000 cargo build --release
/// ```
/// The default value is defined in `Cargo.toml` under `[package.metadata.hades]`.
/// The value can still be overridden at **runtime** via `--url`.
pub const DEFAULT_GRPC_ADDR: &str = env!("GRPC_ADDR");

/// gRPC server address.  Defaults to [`DEFAULT_GRPC_ADDR`].
/// Set via CLI before the first `get_connection` call; include the URL scheme.
pub static GRPC_ADDR: OnceLock<String> = OnceLock::new();

/// When `true`, connect without TLS (development / local env).
pub static INSECURE_TRANSPORT: AtomicBool = AtomicBool::new(false);

/// When `true`, skip SNI domain verification.
///
/// NOTE: tonic 0.12 does not expose `InsecureSkipVerify` in `ClientTlsConfig`.
/// Setting this flag omits the `domain_name` SNI check, which is the closest
/// approximation without implementing a custom `rustls::client::ServerCertVerifier`.
pub static INSECURE_TLS: AtomicBool = AtomicBool::new(false);

static CA_CERT:     &[u8] = include_bytes!("../../tls/ca.crt");
static CLIENT_CERT: &[u8] = include_bytes!("../../tls/client.crt");
static CLIENT_KEY:  &[u8] = include_bytes!("../../tls/client.key");

// tonic 0.12 does not expose a `WithStatsHandler` dial-option equivalent.
// Wire-byte accounting is therefore updated manually by the send/receive paths.

pub struct StatsHandler {
    /// Bytes received since the last `get_stats()` call.
    pub rx_bytes: AtomicU64,
    /// Bytes transmitted since the last `get_stats()` call.
    pub tx_bytes: AtomicU64,
    last_sample:  Mutex<Instant>,
}

pub struct Stats {
    /// Receive throughput in bytes / second.
    pub rx_speed: f64,
    /// Transmit throughput in bytes / second.
    pub tx_speed: f64,
}

impl StatsHandler {
    fn new() -> Self {
        Self {
            rx_bytes:    AtomicU64::new(0),
            tx_bytes:    AtomicU64::new(0),
            last_sample: Mutex::new(Instant::now()),
        }
    }

    /// Returns Rx/Tx speed in bytes-per-second and resets the byte counters.
    pub fn get_stats(&self) -> Stats {
        let now     = Instant::now();
        let mut last = self.last_sample.lock().unwrap();
        let elapsed  = now.duration_since(*last).as_secs_f64();
        *last = now;
        if elapsed > 0.0 {
            Stats {
                rx_speed: self.rx_bytes.swap(0, Ordering::Relaxed) as f64 / elapsed,
                tx_speed: self.tx_bytes.swap(0, Ordering::Relaxed) as f64 / elapsed,
            }
        } else {
            Stats { rx_speed: 0.0, tx_speed: 0.0 }
        }
    }
}

static DEFAULT_STATS_HANDLER: LazyLock<StatsHandler> = LazyLock::new(StatsHandler::new);

/// Returns a reference to the process-global [`StatsHandler`] instance.
pub fn stats_handler() -> &'static StatsHandler { &DEFAULT_STATS_HANDLER }

/// Build the mTLS `ClientTlsConfig`.
///
/// - `INSECURE_TLS=false` → full mTLS with CA chain + SNI `"hades.com"`.
/// - `INSECURE_TLS=true`  → mTLS without SNI enforcement.
fn build_tls_config() -> anyhow::Result<ClientTlsConfig> {
    let ca = Certificate::from_pem(CA_CERT);
    let id = Identity::from_pem(CLIENT_CERT, CLIENT_KEY);
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(ca)
        .identity(id);
    if !INSECURE_TLS.load(Ordering::Relaxed) {
        tls = tls.domain_name("hades.com");
    }
    Ok(tls)
}

/// Lazily-connected `Channel`, created once and shared across all sessions.
///
/// `connect_lazy()` returns immediately; tonic dials on the first RPC and
/// reconnects automatically via HTTP/2 keepalive PING frames.
static CONNECTION: OnceLock<Channel> = OnceLock::new();

/// Return the shared `Channel`, building it on first call.
///
/// Connection lifecycle (jitter, session-level backoff) is owned by `startup()`
/// in `client.rs`. This function is a pure factory: it constructs the endpoint
/// once, stores it, and returns a cheap clone on subsequent calls.
pub fn get_connection() -> anyhow::Result<Channel> {
    if let Some(ch) = CONNECTION.get() {
        return Ok(ch.clone());
    }

    let addr = GRPC_ADDR
        .get()
        .map(|s| s.as_str())
        .unwrap_or(DEFAULT_GRPC_ADDR);

    log::info!(
        "addr: {addr}, insecure: {}, insecure-tls: {}",
        INSECURE_TRANSPORT.load(Ordering::Relaxed),
        INSECURE_TLS.load(Ordering::Relaxed),
    );

    let ep = Channel::from_shared(addr.to_owned())?
        .connect_timeout(Duration::from_secs(3))
        .http2_keep_alive_interval(Duration::from_secs(10))
        .keep_alive_timeout(Duration::from_secs(20))
        .keep_alive_while_idle(true);

    let ep = if INSECURE_TRANSPORT.load(Ordering::Relaxed) {
        ep
    } else {
        ep.tls_config(build_tls_config()?)?
    };

    let ch = ep.connect_lazy();
    let _ = CONNECTION.set(ch.clone());
    Ok(ch)
}
