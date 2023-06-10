use anyhow::Result;

pub mod event;
pub mod tc;

pub trait BpfProgram {
    /// init he bpf program
    fn init(&mut self) -> Result<()>;
    
    /// attach bpf binary
    fn attach(&mut self) -> Result<()>;

    /// detech the binary, wrapper the destory method inside if it is needed
    fn detech(&mut self) -> Result<()>;

    /// status of the bpf program
    fn status(&self) -> bool;
}