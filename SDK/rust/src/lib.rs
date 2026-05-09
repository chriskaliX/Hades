//! Hades agent SDK.
//!
//! ```text
//! SDK/rust/src/
//!   transport/
//!     client.rs   — plugin-side pipe Client (fd 3/4)
//!     server.rs   — agent-side Server (process + I/O threads)
//!     protocol.rs — prost-generated Record / Task / Payload
//!   logger.rs
//!   hash.rs
//! ```

pub mod transport;
pub mod logger;
pub mod hash;

pub use transport::Client;
pub use transport::{Payload, Record, Task};
pub use transport::{Server, ServerSnapshot};
