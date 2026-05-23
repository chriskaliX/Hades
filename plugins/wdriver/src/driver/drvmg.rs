use std::{fs, io::Read, path::PathBuf, ptr::{null, null_mut}, result};
use windows::{
    core::*, 
    Win32::System::IO::*,
    Win32::Foundation::*, 
    Win32::System::Threading::*,
    Win32::Storage::FileSystem::*, 
};

pub struct DrivenManageImpl {
    pub handle: HANDLE,
}

impl DrivenManageImpl {
    pub fn new() -> Self {
        Self { handle: HANDLE(null_mut()) }
    }

    // Chekcout Driver Status
    pub fn get_driver_stu(driver_name: String) -> bool {
        
        return true;
    }

    // Open DriverHandle
    pub fn open_driver_handle(&mut self, driver_name: String) -> bool {
        unsafe {
            let attribute: u32 = 2147483648u32 | 1073741824u32;
            let result: std::prelude::v1::Result<HANDLE, Error> = CreateFileA(
                PCSTR(driver_name.as_ptr()),
                attribute,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            );
            if result.is_ok() {
                let driver_handle: HANDLE = result.unwrap();
                self.handle = driver_handle;
                return true;
            } else {
                let err  = GetLastError();
                println!("{}", err.to_hresult().0);
                return false;
            }
        }
    }

    // Send Data Pop Data
    pub async  fn send_driver_data(&self, _code: u32, _data: String) -> bool {

        return true;
    }

    // Read Data Push Queue
    pub async fn read_driver_data(&self) {

    }

    pub fn close_driver_handle(&mut self) {
        if self.handle.is_invalid(){
            return;
        }
        unsafe {
            let _ = CloseHandle(self.handle);
        }
        self.handle = HANDLE(null_mut());
    }

}
