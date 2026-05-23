use wdriver::appcore::app_account;
use wdriver::appcore::app_autostart;
use wdriver::appcore::app_include;
use wdriver::appcore::app_net;
use wdriver::appcore::app_process;
use wdriver::appcore::app_service_software;

#[test]
pub fn unit_test_account() {
    let b = app_account::AppAccount::init();
    if b {
        println!("account init success.");
    }
}

#[test]
pub fn unit_test_network() {
    let b = app_net::AppNetwork::init();
    if b {
        println!("network init success.");
    }
}

#[test]
pub fn unit_test_processinfo() {
    let b = app_process::AppProcess::init();
    if b {
        println!("process init success.");
    }
}

#[test]
pub fn unit_test_servicesinfo() {
    let mut serivce_info: Vec<app_include::AppServiceInfo> = vec![];
    let b = app_service_software::AppServiceSoftWare::get_services_info(&mut serivce_info);
    if b {
        println!("service init success.");
    }
}

#[test]
pub fn unit_test_softwareinfo() {
    let mut software_info: Vec<app_include::AppSoftWareInfo> = vec![];
    let b = app_service_software::AppServiceSoftWare::get_software_info(&mut software_info);
    if b {
        println!("software init success.");
    }
}

#[test]
pub fn unit_test_astart_register() {
    let mut astart_register: Vec<app_include::AppRegRunInfo> = vec![];
    let b = app_autostart::AppAutoStart::get_astart_register(&mut astart_register);
    if b {
        println!("astart_register init success.");
    }
}
