#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub cmdline: Option<String>,
}
