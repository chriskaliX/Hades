use crate::{
    appcore::app_include::AppServiceInfo, appcore::app_include::AppSoftWareInfo,
    util::windows_installed::App,
};
use windows::{
    core::PCWSTR,
    Win32::System::Services::{
        CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW,
        QueryServiceConfig2W, QueryServiceConfigW, ENUM_SERVICE_STATE, ENUM_SERVICE_STATUS_PROCESSW,
        ENUM_SERVICE_TYPE, QUERY_SERVICE_CONFIGW, SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE,
        SERVICE_CONFIG_DESCRIPTION, SERVICE_DESCRIPTIONW, SERVICE_QUERY_CONFIG,
        SERVICE_STATE_ALL, SERVICE_WIN32,
    },
};

pub struct AppServiceSoftWare {
    pub services_info: Vec<AppServiceInfo>,
    pub software_info: Vec<AppSoftWareInfo>,
}

impl AppServiceSoftWare {
    const MAX_SERVICES: usize = 4096;

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
        unsafe {
            let scm = match OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) {
                Ok(handle) => handle,
                Err(_) => return false,
            };

            let mut bytes_needed = 0u32;
            let mut services_returned = 0u32;
            let mut resume_handle = 0u32;

            let _ = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                ENUM_SERVICE_TYPE(SERVICE_WIN32.0),
                ENUM_SERVICE_STATE(SERVICE_STATE_ALL.0),
                None,
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                PCWSTR::null(),
            );

            if bytes_needed == 0 {
                let _ = CloseServiceHandle(scm);
                return false;
            }

            let mut buffer = vec![0u8; bytes_needed as usize];
            if EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                ENUM_SERVICE_TYPE(SERVICE_WIN32.0),
                ENUM_SERVICE_STATE(SERVICE_STATE_ALL.0),
                Some(buffer.as_mut_slice()),
                &mut bytes_needed,
                &mut services_returned,
                Some(&mut resume_handle),
                PCWSTR::null(),
            )
            .is_err()
            {
                let _ = CloseServiceHandle(scm);
                return false;
            }

            let entries = std::slice::from_raw_parts(
                buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                services_returned as usize,
            );

            for entry in entries.iter().take(Self::MAX_SERVICES) {
                let service_name = pwstr_to_string(entry.lpServiceName.0);
                if service_name.is_empty() {
                    continue;
                }

                let (binary_path, description) = query_service_details(scm, &service_name);
                services_info.push(AppServiceInfo {
                    displayname: pwstr_to_string(entry.lpDisplayName.0),
                    servicename: service_name,
                    binarypath: binary_path,
                    description,
                    currentstate: service_state_text(entry.ServiceStatusProcess.dwCurrentState.0),
                });
            }

            let _ = CloseServiceHandle(scm);
        }
        !services_info.is_empty()
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

fn query_service_details(
    scm: windows::Win32::System::Services::SC_HANDLE,
    service_name: &str,
) -> (String, String) {
    unsafe {
        let wide_name = wide_null(service_name);
        let service = match OpenServiceW(scm, PCWSTR(wide_name.as_ptr()), SERVICE_QUERY_CONFIG) {
            Ok(handle) => handle,
            Err(_) => return (String::new(), String::new()),
        };

        let mut bytes_needed = 0u32;
        let _ = QueryServiceConfigW(service, None, 0, &mut bytes_needed);
        let mut binary_path = String::new();
        if bytes_needed > 0 {
            let mut buffer = vec![0u8; bytes_needed as usize];
            let config = buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
            if QueryServiceConfigW(service, Some(config), bytes_needed, &mut bytes_needed).is_ok() {
                binary_path = pwstr_to_string((*config).lpBinaryPathName.0);
            }
        }

        let mut desc_needed = 0u32;
        let _ = QueryServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, None, &mut desc_needed);
        let mut description = String::new();
        if desc_needed > 0 {
            let mut buffer = vec![0u8; desc_needed as usize];
            if QueryServiceConfig2W(
                service,
                SERVICE_CONFIG_DESCRIPTION,
                Some(buffer.as_mut_slice()),
                &mut desc_needed,
            )
            .is_ok()
            {
                let desc = buffer.as_ptr() as *const SERVICE_DESCRIPTIONW;
                description = pwstr_to_string((*desc).lpDescription.0);
            }
        }

        let _ = CloseServiceHandle(service);
        (binary_path, description)
    }
}

fn pwstr_to_string(ptr: *mut u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

fn service_state_text(state: u32) -> String {
    match state {
        1 => "STOPPED",
        2 => "START_PENDING",
        3 => "STOP_PENDING",
        4 => "RUNNING",
        5 => "CONTINUE_PENDING",
        6 => "PAUSE_PENDING",
        7 => "PAUSED",
        _ => "UNKNOWN",
    }
    .to_string()
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
