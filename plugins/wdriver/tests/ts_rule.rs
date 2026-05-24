use fast_log::{
    config,
    consts::LogSize,
    plugin::{file_split::RollingType, packer::LogPacker},
};
use std::{
    thread::{self, current},
    time,
};
use tokio::{
    io::AsyncWriteExt,
    runtime::Runtime,
    sync::{mpsc::Sender, RwLock},
    task::JoinHandle,
};

use wdriver::config::config::*;

#[test]
pub fn unit_get_dns_rule() {
    let runtime = tokio::runtime::Runtime::new().ok().unwrap();
    runtime.spawn(async move {
        let reply = RuleImpl::init().await;
        if false == reply {
            println!("rule init.");
        }
    });

    let ten_millis = time::Duration::from_millis(100000);
    thread::sleep(ten_millis);
}
