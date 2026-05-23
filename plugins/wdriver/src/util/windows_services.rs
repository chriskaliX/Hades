use windows::{
    Win32::Foundation::*, 
    Win32::System::Threading::*,
    Win32::System::Services::*,
};

use std::ptr::{null_mut};

pub struct Service;

impl Service {

    pub unsafe fn get_services_info() {

        // let schandle = OpenSCManagerA (
             
        //     0 as i32, 
        //     SC_MANAGER_ENUMERATE_SERVICE
        // );
        // println!("schandle: {:x?}",schandle);

        // let mut bytesneeded = 0;
        // let mut numofservices = 0;
        // EnumServicesStatusExA(
        //     schandle.unwrap(), 
        //     SC_ENUM_PROCESS_INFO, 
        //     SERVICE_WIN32, 
        //     SERVICE_STATE_ALL, 
        //     std::ptr::null_mut(), 
        //     0, 
        //     &mut bytesneeded, 
        //     &mut numofservices, 
        //     std::ptr::null_mut(), 
        //     std::ptr::null_mut()
        // );

        // println!("bytes needed: {}",bytesneeded);
        // println!("number of services : {}",numofservices);

        // let baseptr = VirtualAlloc(
        //     std::ptr::null_mut(), 
        //     bytesneeded as usize, 
        //     0x1000|0x2000, 0x40
        // );
        // EnumServicesStatusExA(
        //     schandle.unwrap(), 
        //     SC_ENUM_PROCESS_INFO, 
        //     SERVICE_WIN32, 
        //     SERVICE_STATE_ALL, 
        //     baseptr as *mut u8, 
        //     bytesneeded, 
        //     &mut bytesneeded, 
        //     &mut numofservices, 
        //     std::ptr::null_mut(), 
        //     std::ptr::null_mut()
        // );

        // println!("bytes needed: {}",bytesneeded);
        // println!("number of services : {}",numofservices);
        
        // //let mut enumservices = std::mem::zeroed::<ENUM_SERVICE_STATUS_PROCESSA>();
        // for i in 0..numofservices{          
        //     let mut enumservices = (*((baseptr as isize + (i as isize *std::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSA>() as isize)) as *mut ENUM_SERVICE_STATUS_PROCESSA));
        //     let dname =  ReadStringFromMemory(GetCurrentProcess(), enumservices.lpDisplayName as *mut c_void);
        //     let sname =  ReadStringFromMemory(GetCurrentProcess(), enumservices.lpServiceName as *mut c_void);
        //     //println!(" service display name: {}",dname);
        //     println!("service name: {}, pid: {}",sname,enumservices.ServiceStatusProcess.dwProcessId);
        //     let servicehandle =  OpenServiceA(
        //         schandle.unwrap(), 
        //             enumservices.lpServiceName, 
        //             SERVICE_QUERY_CONFIG
        //         );
        //     let mut sbytes = 0;
        //     QueryServiceConfigA(
        //         servicehandle.unwrap(), 
        //         std::ptr::null_mut(), 
        //         0, &mut sbytes);
        //     let sbase =VirtualAlloc(std::ptr::null_mut(), sbytes as usize, 0x1000|0x2000, 0x40);
        //     QueryServiceConfigA(
        //         servicehandle.unwrap(), 
        //         sbase as *mut QUERY_SERVICE_CONFIGA, 
        //         sbytes, &mut sbytes);
        //     let sconfig = (*(sbase as *mut QUERY_SERVICE_CONFIGA));
        //     let binpath = ReadStringFromMemory(
        //         GetCurrentProcess(), 
        //         sconfig.lpBinaryPathName as *mut c_void
        //     );
        //     if !binpath.contains("\""){
        //         println!("binary path: {}",binpath);
        //         VirtualFree(sbase, 0, 0x8000);
        //     } 
        // }

        // Foundation::VirtualFree(baseptr, 0, 0x8000);
        // /*let mut bytesneeded = 0;

        // let res = QueryServiceConfigA(schandle, 
        //     std::ptr::null_mut(), 
        //     0, &mut bytesneeded);

        //     println!("res: {}",res);
        //     println!("getlasterror: {}",GetLastError());
        //     println!("bytes needed: {}",bytesneeded );
        // */
    }
}