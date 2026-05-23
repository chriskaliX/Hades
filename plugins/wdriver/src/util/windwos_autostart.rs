use std::borrow::Cow;
use std::error::Error;
use std::fmt::Debug;
use winreg::enums::*;
use winreg::reg_key::RegKey;
use winreg::reg_value::RegValue;
use winreg::HKEY;

thread_local! {
    static UNINSTALLS: Option<RegKey> = None;
}

pub struct App {
    name: String,
    reg: RegValue,
}
struct AppList {
    autostart: RegKey,
    index: usize,
}
impl Iterator for AppList {
    type Item = App;
    fn next(&mut self) -> Option<Self::Item> {
        let value_= self.autostart.enum_values().nth(self.index)?.ok()?;
        self.index += 1;
        Some(App { 
            name: value_.0,
            reg: value_.1 
        })
    }
}
impl AppList {
    fn new(hive: HKEY, path: &str) -> Result<Self, Box<dyn Error>> {
        let hive = RegKey::predef(hive);
        let autostart = hive.open_subkey(path)?;

        Ok(AppList {
            autostart,
            index: 0,
        })
    }
}
impl App {
    pub fn get_key(&self) -> String {
        self.name.to_string()
    }
    pub fn get_value(&self) -> String {
        self.reg.to_string()
    }
    pub fn list() -> Result<impl Iterator<Item = App>, Box<dyn Error>> {
        let system_apps = AppList::new(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        .ok()
        .into_iter()
        .flatten();
        let system_apps_32 = AppList::new(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        .ok()
        .into_iter()
        .flatten();
        let user_apps = AppList::new(
            HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        .ok()
        .into_iter()
        .flatten();
        // this one may not exist
        let user_apps_32 = AppList::new(
            HKEY_CURRENT_USER,
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        .ok()
        .into_iter()
        .flatten();
        let system_apps_runonce = AppList::new(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Runonce",
        )
        .ok()
        .into_iter()
        .flatten();

        let chain = system_apps
            .chain(system_apps_32)
            .chain(user_apps)
            .chain(user_apps_32)
            .chain(system_apps_runonce);

        Ok(chain)
    }
}