use crate::{
    appcore::app_include::AppServiceInfo, appcore::app_include::AppSoftWareInfo,
    util::windows_installed::App,
};

pub struct AppServiceSoftWare {
    pub services_info: Vec<AppServiceInfo>,
    pub software_info: Vec<AppSoftWareInfo>,
}

impl AppServiceSoftWare {
    pub fn init() -> bool {
        let mut services_info: Vec<AppServiceInfo> = vec![];
        let mut software_info: Vec<AppSoftWareInfo> = vec![];

        Self::get_services_info(&mut services_info);
        Self::get_software_info(&mut software_info);

        Self {
            services_info: services_info,
            software_info: software_info,
        };
        return true;
    }

    pub fn get_services_info(services_info: &mut Vec<AppServiceInfo>) -> bool {
        if services_info.is_empty() {
            return false;
        }
        return true;
    }

    pub fn get_software_info(software_info: &mut Vec<AppSoftWareInfo>) -> bool {
        // read uninstall register valuse
        let apps = match App::list() {
            Ok(apps) => apps,
            Err(_) => return false,
        };
        for app in apps {
            let installpath = if app.install_path().is_empty() {
                app.installlocal_path().into_owned()
            } else {
                app.install_path().into_owned()
            };
            let software_ctx = AppSoftWareInfo {
                name: app.name().into_owned(),
                version: app.version().into_owned(),
                helplink: app.helplink().into_owned(),
                size: app.size().into_owned(),
                insatllpath: installpath,
                uninstallpath: app.uninstall_path().into_owned(),
                venrel: app.publisher().into_owned(),
                icopath: app.icon().into_owned(),
            };

            software_info.push(software_ctx);
        }

        if software_info.is_empty() {
            return false;
        }
        return true;
    }
}
