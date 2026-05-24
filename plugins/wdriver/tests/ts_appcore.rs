use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use wdriver::appcore::{
    app_account::AppAccount, app_autostart::AppAutoStart, app_file::AppFile,
    app_include::{
        AppFileExInfo, AppFileInfo, AppRegRunInfo, AppServiceInfo, AppSoftWareInfo,
        AppTaskSchedulerRunInfo,
    },
    app_net::AppNetwork, app_process::AppProcess, app_service_software::AppServiceSoftWare,
};

#[test]
fn unit_collect_process_snapshot() {
    let mut items = Vec::new();
    assert!(AppProcess::get_process_info(&mut items));
    assert!(!items.is_empty());
    assert!(items.iter().any(|item| item.pid > 0));
}

#[test]
fn unit_collect_network_snapshot() {
    let mut items = Vec::new();
    assert!(AppNetwork::get_socket_info(&mut items));
    assert!(!items.is_empty());
    assert!(
        items.iter()
            .all(|item| !item.protocol.is_empty() && !item.localaddress.is_empty())
    );
}

#[test]
fn unit_collect_account_snapshot() {
    let mut items = Vec::new();
    assert!(AppAccount::get_account_info(&mut items));
    assert!(!items.is_empty());
    assert!(items.iter().all(|item| !item.serveruser.is_empty()));
}

#[test]
fn unit_collect_autorun_registry_snapshot() {
    let mut items: Vec<AppRegRunInfo> = vec![];
    assert!(AppAutoStart::get_astart_register(&mut items));
    assert!(!items.is_empty());
}

#[test]
fn unit_collect_autorun_task_scheduler_snapshot() {
    let mut items: Vec<AppTaskSchedulerRunInfo> = vec![];
    assert!(AppAutoStart::get_astart_taskschedu(&mut items));
    assert!(!items.is_empty());
    assert!(items.iter().any(|item| !item.valuename.is_empty()));
}

#[test]
fn unit_collect_service_snapshot() {
    let mut items: Vec<AppServiceInfo> = vec![];
    assert!(AppServiceSoftWare::get_services_info(&mut items));
    assert!(!items.is_empty());
    assert!(items.iter().any(|item| !item.servicename.is_empty()));
}

#[test]
fn unit_collect_software_snapshot() {
    let mut items: Vec<AppSoftWareInfo> = vec![];
    assert!(AppServiceSoftWare::get_software_info(&mut items));
    assert!(!items.is_empty());
    assert!(items.iter().any(|item| !item.name.is_empty()));
}

#[test]
fn unit_collect_directory_and_file_snapshot() {
    let temp_dir = unique_temp_dir();
    fs::create_dir_all(&temp_dir).expect("create temp dir");
    let file_path = temp_dir.join("sample.txt");
    fs::write(&file_path, b"wdriver-test-payload").expect("write sample file");

    let direct = AppFile::get_directory_info(temp_dir.to_string_lossy().as_ref())
        .expect("directory collection");
    assert!(direct.filecount >= 1);
    assert!(direct.file_array.iter().any(|item: &AppFileInfo| item.filename == "sample.txt"));

    let file: AppFileExInfo = AppFile::get_file_info(file_path.to_string_lossy().as_ref())
        .expect("file collection");
    assert_eq!(file.filename, "sample.txt");
    assert!(!file.filemd5.is_empty());

    let _ = fs::remove_file(file_path);
    let _ = fs::remove_dir_all(temp_dir);
}

fn unique_temp_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift")
        .as_nanos();
    std::env::temp_dir().join(format!("wdriver-appcore-{}", suffix))
}
