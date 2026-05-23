use sysinfo::*;

use crate::appcore::app_include::AppProcessInfo;

pub struct AppProcess {
    pub process_info: Vec<AppProcessInfo>,
}

impl AppProcess {
    pub fn init() -> bool {
        let mut process_info: Vec<AppProcessInfo> = vec![];
        let b_ok = Self::get_process_info(&mut process_info);
        if false == b_ok {
            return false;
        }

        Self {
            process_info: process_info,
        };
        return true;
    }

    pub fn get_process_info(process_info: &mut Vec<AppProcessInfo>) -> bool {
        let mut sysinfo = System::new_all();
        sysinfo.refresh_processes(ProcessesToUpdate::All, true);

        for (pid, process) in sysinfo.processes() {
            let mut cmdline = "".to_string();
            for s in process.cmd() {
                if s.is_empty() {
                    continue;
                }
                cmdline.push_str(s.to_string_lossy().as_ref());
                cmdline.push_str("|");
            }
            let process_ctx = AppProcessInfo {
                pid: pid.as_u32(),
                th32parentprocessid: process.parent().map(|pid| pid.as_u32()).unwrap_or(0),
                exefile: process.name().to_string_lossy().into_owned(),
                priclassbase: process.status().to_string(),
                threadcount: 0,
                processfullpath: cmdline,
            };
            process_info.push(process_ctx);
        }

        if process_info.is_empty() {
            return false;
        }
        return true;
    }
}
