// use anyhow::Result;

// #[derive(Debug, Clone, Default)]
// pub struct ProcessInfo {
//     pub pid: u32,
//     pub cmdline: Option<String>,
//     pub exe_name: Option<String>,
//     pub exe_path: Option<String>,
//     pub maps: Option<Vec<Map>>,
// }

// impl ProcessInfo {
//     pub fn from_pid(pid: u32) -> Result<Self> {
//         Ok(())
//     }

//     pub fn read_cmdline(&mut self) -> Result<String> {
//         let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid))?;
//     }
// }
