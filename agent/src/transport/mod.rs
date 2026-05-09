/// gRPC transport layer.
///
/// Module layout (mirrors the Go `transport/` package):
///   client.rs     — startup loop, handle_send, handle_receive  (`client.go`)
///   transfer.rs   — Transfer buffer, TPS counters, command dispatch (`transfer.go`)
///   connection.rs — mTLS channel management, reconnect back-off  (`connection/`)
///   file.rs       — file upload via FileExt RPC                 (`file.go`)
pub mod client;
pub mod connection;
pub mod download;
pub mod file;
pub mod transfer;



