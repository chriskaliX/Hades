mod agent;
mod log;
mod metrics;
mod plugin;
mod proto;
mod transport;

use clap::Parser;
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

// Shadow the `log` crate macros explicitly so they don't conflict with `mod log`.
use ::log::{info, warn};

/// Hades agent — command-line options mirror agent/main.go.
#[derive(Parser)]
struct Cli {
    /// gRPC server address (include scheme, e.g. https://host:8000)
    #[arg(long, default_value = transport::connection::DEFAULT_GRPC_ADDR)]
    url: String,

    /// Connect without TLS (dev / local env)
    #[arg(long, default_value_t = false)]
    insecure: bool,

    /// Skip TLS SNI domain verification
    #[arg(long = "insecure-tls", default_value_t = false)]
    insecure_tls: bool,
}

#[tokio::main]
async fn main() {
    let _ = log::init();

    let cli = Cli::parse();

    // Apply CLI flags to connection globals — must be set before first connect.
    transport::connection::GRPC_ADDR.set(cli.url).ok();
    transport::connection::INSECURE_TRANSPORT
        .store(cli.insecure, std::sync::atomic::Ordering::Relaxed);
    transport::connection::INSECURE_TLS
        .store(cli.insecure_tls, std::sync::atomic::Ordering::Relaxed);

    info!("agent starts, version: {}", agent::VERSION);

    // Mirror Go: when running under sysvinit, acquire an exclusive PID-file
    // lock so only one instance runs at a time.
    // Uses flock(LOCK_EX|LOCK_NB) — same semantic as nightlyone/lockfile.
    if std::env::var("service_type").as_deref() == Ok("sysvinit") {
        let pid_path = format!("{}{}.pid",
            agent::PIDPATH, agent::PRODUCT);
        if let Err(e) = acquire_pid_lock(&pid_path) {
            eprintln!("lockfile {pid_path} failed: {e}");
            return;
        }
    }

    let token = CancellationToken::new();
    let mut tasks = JoinSet::new();

    // Signal handler: SIGTERM (systemd/kill) and SIGINT (Ctrl+C).
    // wait signal → log → sleep 3 s → cancel (workers then detect and stop).
    let sig_token = token.clone();
    tasks.spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut sigint  = signal(SignalKind::interrupt()).expect("SIGINT handler");
        tokio::select! {
            _ = sigterm.recv() => warn!("receive signal: SIGTERM"),
            _ = sigint.recv()  => warn!("receive signal: SIGINT"),
        }
        info!("wait for 3 secs to exit");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        sig_token.cancel();
    });

    // Worker tasks — equivalent to go plugin.Startup / go metrics.Startup / go transport.Startup.
    // transport finishing also cancels the token, same as Go's `agent.Cancel()` after transport.Startup.
    let transport_token = token.clone();
    tasks.spawn(plugin::startup(token.child_token()));
    tasks.spawn(metrics::startup(token.child_token()));
    tasks.spawn(async move {
        transport::client::startup(transport_token.child_token()).await;
        transport_token.cancel(); // mirrors: go func() { transport.Startup(...); agent.Cancel() }()
    });

    // wg.Wait() — block until all workers have returned.
    tasks.join_all().await;

    info!("agent is stop");
}

/// Acquire an exclusive non-blocking flock on `path`, writing the current PID.
/// Mirrors Go's `lockfile.New(path).TryLock()` (nightlyone/lockfile).
#[cfg(unix)]
fn acquire_pid_lock(path: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::io::AsRawFd;
    let file = std::fs::OpenOptions::new()
        .create(true).write(true).truncate(true)
        .open(path)?;
    // LOCK_EX | LOCK_NB: fail immediately if another instance holds the lock.
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Write PID so sysvinit / monitoring scripts can inspect it.
    let mut f = file;
    writeln!(f, "{}", std::process::id())?;
    // Intentionally leak `f`: the lock is held for the process lifetime.
    std::mem::forget(f);
    Ok(())
}
