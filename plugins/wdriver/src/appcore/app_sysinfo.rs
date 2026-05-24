pub struct AppSysInfo {
    pub cpu: String,
    pub name: String,
    pub os_version: String,
    pub display_card: Vec<String>,
    pub camera: Vec<String>,
    pub bluetooth: Vec<String>,
    pub voice: Vec<String>,
    pub microphone: Vec<String>,
}

impl AppSysInfo {
    pub fn init() {}

    pub fn get_computer_name() {}

    pub fn get_os_version() {}

    pub fn get_display_cardinfo_wmic() {}

    pub fn get_cpu_info() {}

    pub fn get_bluetooth_info() {}

    pub fn get_camera_info() {}

    pub fn get_micro_phone() {}

    pub fn get_gpu_info() {}
}
