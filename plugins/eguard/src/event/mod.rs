use anyhow::Result;

use crate::config::config::Config;

pub mod egress;
pub mod event;
pub mod ip_address;

pub trait BpfProgram {
    /// init he bpf program
    fn init(&mut self) -> Result<()>;

    /// attach bpf binary
    fn attach(&mut self) -> Result<()>;

    /// detech the binary, wrapper the destory method inside if it is needed
    fn detech(&mut self) -> Result<()>;

    /// status of the bpf program
    fn status(&self) -> bool;

    /// flush configuration into this
    fn flush_config(&self, config: Config) -> Result<()>;
}
