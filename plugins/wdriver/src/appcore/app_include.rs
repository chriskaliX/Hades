use serde::{Deserialize, Serialize};

// account 
pub struct AppAccountInfo {
    pub serveruser: String,
    pub servername: String,
    pub serverusid: String,
    pub serverflag: u32,
}

// auto start 
pub struct AppRegRunInfo {
    pub valuename: String,
    pub valuekey: String,
}
pub struct AppTaskSchedulerRunInfo {
    pub valuename: String,
    pub state: u32,
    pub lastime: u64,
    pub nexttime: u64,
    pub taskcommand: String,
}

// file
pub struct AppFileExInfo {
    pub filename: String,
    pub filecreate: String,
    pub filemodify: String,
    pub fileaccess: String,
    pub fileattributes:String,
    pub filesize: String,
    pub fileattributes_hide:String,
    pub filepath: String,
    pub filemd5: String
}
pub struct AppFileInfo{
    pub filesize: u32,
    pub filename: String,
    pub filepath: String,
}
pub struct AppDriectInfo {
    pub directname:  String,
    pub directsize: u32,
    pub filecount: u32,
    pub file_array: Vec<AppFileInfo>, 
}

// network
pub struct AppNetWorkInfo {
    pub pid: u32,
    pub th32parentprocessid: u32,
    pub processname: String,
    pub cmd: String,
    pub protocol: String,
    pub localaddress: String,
    pub remoteaddress: String,
    pub localport: u32,
    pub remoteport: u32,
    pub state: String,
}

// process 
pub struct  AppProcessInfo {
    pub pid : u32,
    pub th32parentprocessid: u32,
    pub exefile: String,
    pub priclassbase: String,
    pub threadcount: u32,
    pub processfullpath: String,
}

// service software
pub struct AppSoftWareInfo {
    pub name: String,
    pub version: String,
    pub helplink: String,
    pub size: String,
    pub insatllpath: String,
    pub uninstallpath: String,
    pub venrel: String,
    pub icopath: String,
}
pub struct AppServiceInfo {
    pub displayname: String,
    pub servicename: String, 
    pub binarypath: String,
    pub description: String,
    pub currentstate: String,
}

