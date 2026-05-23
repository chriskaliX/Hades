use crate::{
    appcore::app_include::AppRegRunInfo, appcore::app_include::AppTaskSchedulerRunInfo,
    util::windwos_autostart::{list_task_scheduler, App},
};

pub struct AppAutoStart {
    pub astart_register: Vec<AppRegRunInfo>,
    pub astart_tasksched: Vec<AppTaskSchedulerRunInfo>,
}

impl AppAutoStart {
    pub fn init() -> bool {
        let mut astart_register: Vec<AppRegRunInfo> = vec![];
        let mut astart_tasksched: Vec<AppTaskSchedulerRunInfo> = vec![];

        let _ = Self::get_astart_register(&mut astart_register);
        let _ = Self::get_astart_taskschedu(&mut astart_tasksched);

        if astart_register.is_empty() && astart_tasksched.is_empty() {
            return false;
        }

        Self {
            astart_register: astart_register,
            astart_tasksched: astart_tasksched,
        };
        return true;
    }

    pub fn get_astart_register(astart_register: &mut Vec<AppRegRunInfo>) -> bool {
        let apps = match App::list() {
            Ok(apps) => apps,
            Err(_) => return false,
        };
        for app in apps {
            let regrun_ctx = AppRegRunInfo {
                valuename: app.get_key(),
                valuekey: app.get_value(),
            };
            astart_register.push(regrun_ctx);
        }
        if astart_register.is_empty() {
            return false;
        }
        return true;
    }

    pub fn get_astart_taskschedu(astart_tasksched: &mut Vec<AppTaskSchedulerRunInfo>) -> bool {
        let tasks = match list_task_scheduler() {
            Ok(tasks) => tasks,
            Err(_) => return false,
        };

        for task in tasks.into_iter().take(1000) {
            astart_tasksched.push(AppTaskSchedulerRunInfo {
                valuename: task.get_name(),
                state: task.get_state(),
                lastime: task.get_last_time(),
                nexttime: task.get_next_time(),
                taskcommand: task.get_command(),
            });
        }

        if astart_tasksched.is_empty() {
            return false;
        }
        return true;
    }
}
