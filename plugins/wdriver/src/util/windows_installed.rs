use std::borrow::Cow;
use std::error::Error;
use winreg::enums::*;
use winreg::reg_key::RegKey;
use winreg::HKEY;

thread_local! {
    static UNINSTALLS: Option<RegKey> = None;
}

pub struct App {
    reg: RegKey,
}
struct AppList {
    uninstalls: RegKey,
    index: usize,
}
impl Iterator for AppList {
    type Item = App;
    fn next(&mut self) -> Option<Self::Item> {
        let key = self.uninstalls.enum_keys().nth(self.index)?.ok()?;
        self.index += 1;
        let reg = self.uninstalls.open_subkey(key).ok()?;
        Some(App { reg })
    }
}
impl AppList {
    fn new(hive: HKEY, path: &str) -> Result<Self, Box<dyn Error>> {
        let hive = RegKey::predef(hive);
        let uninstalls = hive.open_subkey(path)?;

        Ok(AppList {
            uninstalls,
            index: 0,
        })
    }
}
impl App {
    fn get_value(&self, name: &str) -> Cow<str> {
        self.reg
            .get_value::<String, &str>(name)
            .map(Cow::Owned)
            .unwrap_or_else(|_| Cow::Borrowed(""))
    }
    pub fn name(&self) -> Cow<str> {
        self.get_value("DisplayName")
    }
    pub fn icon(&self) -> Cow<str> {
        self.get_value("DisplayIcon")
    }
    pub fn publisher(&self) -> Cow<str> {
        self.get_value("Publisher")
    }
    pub fn version(&self) -> Cow<str> {
        self.get_value("DisplayVersion")
    }
    pub fn size(&self) -> Cow<str> {
        self.get_value("Size")
    }
    pub fn helplink(&self) -> Cow<str> {
        self.get_value("HelpLink")
    }
    pub fn install_path(&self) -> Cow<str> {
        self.get_value("InstallLocation")
    }
    pub fn installlocal_path(&self) -> Cow<str> {
        self.get_value("InstallLocation")
    }
    pub fn uninstall_path(&self) -> Cow<str> {
        self.get_value("UninstallString")
    }
    pub fn dump(&self) -> Cow<str> {
        self.reg
            .enum_values()
            .map(|r| {
                let (name, value) = r.unwrap();
                format!("{}: {}\n", name, value)
            })
            .collect::<String>()
            .into()
    }
    pub fn list() -> Result<impl Iterator<Item = App>, Box<dyn Error>> {
        let system_apps = AppList::new(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        )
        .ok()
        .into_iter()
        .flatten();
        let system_apps_32 = AppList::new(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        )
        .ok()
        .into_iter()
        .flatten();
        let user_apps = AppList::new(
            HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        )
        .ok()
        .into_iter()
        .flatten();
        // this one may not exist
        let user_apps_32 = AppList::new(
            HKEY_CURRENT_USER,
            "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        )
        .ok()
        .into_iter()
        .flatten();

        let chain = system_apps
            .chain(system_apps_32)
            .chain(user_apps)
            .chain(user_apps_32);

        Ok(chain)
    }
}
