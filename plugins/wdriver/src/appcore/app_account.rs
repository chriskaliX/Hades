use sysinfo::Users;

use crate::{appcore::app_include::AppAccountInfo};

pub struct AppAccount {
    pub account_info: Vec<AppAccountInfo>,
}

impl AppAccount {
    pub fn init() -> bool {
        let mut account_info: Vec<AppAccountInfo> = vec![];
        let bOk = Self::get_account_info(&mut account_info);
        if false == bOk {
            return false;
        }

        Self {
            account_info: account_info,
        };
        return true;
    }

    pub fn get_account_info(account_info:&mut Vec<AppAccountInfo>) -> bool {
        let users = Users::new_with_refreshed_list();
        for user in users.list() {
            let account_ctx = AppAccountInfo{
                serveruser: user.name().to_string(),
                servername: user.name().to_string(),
                serverusid: user.id().to_string(),
                serverflag: 0,
            };
            account_info.push(account_ctx);
        }
        if account_info.is_empty() {
            return false;
        }
        return true;
    }
    
}