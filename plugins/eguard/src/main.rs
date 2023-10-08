// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use anyhow::Result;
use crossbeam::channel::bounded;
use event::tc::TcEvent;
use log::set_boxed_logger;
use log::*;
use sdk::{logger::*, Client};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::config::config::Config as BpfConfig;
use crate::event::dns::DnsEvent;
use crate::manager::manager::Bpfmanager;

mod config;
mod event;
mod manager;

pub const TYPE_TC: u32 = 3200;
pub const TYPE_DNS: u32 = 3201;

fn main() -> Result<()> {
    let mut client = Client::new(false);
    set_boxed_logger(Box::new(Logger::new(Config {
        max_size: 1024 * 1024 * 5,
        path: PathBuf::from("./eguard.log"),
        #[cfg(not(feature = "debug"))]
        file_level: LevelFilter::Info,
        #[cfg(feature = "debug")]
        file_level: LevelFilter::Debug,
        remote_level: LevelFilter::Error,
        max_backups: 10,
        compress: true,
        client: Some(client.clone()),
    })))?;

    // Install Ctrl-C handler
    let control_s = Arc::new(AtomicBool::new(false));
    let control_l = control_s.clone();
    let control_c = control_s.clone();
    ctrlc::set_handler(move || {
        control_c.store(true, Ordering::SeqCst);
    })?;

    // set channel and replace
    let (tx, rx) = bounded(512);
    {
        let mut lock = event::event::TX
            .lock()
            .map_err(|e| error!("failed to define shared notification sender: {}", e))
            .unwrap();
        *lock = Some(tx);
    }

    // tc egress restriction
    Bpfmanager::bump_memlock_rlimit()?;
    let mgr: Arc<Mutex<Bpfmanager>> = Arc::new(Mutex::new(Bpfmanager::new()?.into()));
    let mgr_c = Arc::clone(&mgr);

    // load event
    let tc_event = TcEvent::new();
    let dns_event = DnsEvent::new();

    {
        let mut guard = mgr.lock().unwrap();
        guard.autoload(TYPE_TC, Box::new(tc_event))?;
        guard.autoload(TYPE_DNS, Box::new(dns_event))?;
    }

    info!("init bpf program successfully");
    // task_receive thread
    let mut client_c = client.clone();
    let timeout = Duration::from_millis(500);

    let record_recv = thread::Builder::new()
        .name("task_receive".to_owned())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                loop {
                    if control_s.load(Ordering::SeqCst) {
                        return;
                    }

                    match tokio::time::timeout(timeout, client_c.receive_async()).await {
                        Ok(result) => match result {
                            Ok(task) => match serde_json::from_str::<BpfConfig>(task.get_data()) {
                                Ok(config) => {
                                    if let Err(e) = mgr_c.lock().unwrap().flush_config(config) {
                                        error!("parse task failed: {}", e);
                                    }
                                }
                                Err(e) => {
                                    error!("parse task failed: {}", e);
                                }
                            },
                            Err(e) => {
                                error!("when receiving task, an error occurred: {}", e);
                                control_s.store(true, Ordering::SeqCst);
                                return;
                            }
                        },
                        Err(_) => {}
                    }
                }
            });
            rt.shutdown_background();
        })?;
    info!("task receive handler is running");
    // record_send thread
    let record_send = thread::Builder::new()
        .name("record_send".to_string())
        .spawn(move || loop {
            if control_l.load(Ordering::SeqCst) {
                break;
            }

            let rec = rx.recv_timeout(timeout);
            match rec {
                Ok(rec) => {
                    if let Err(err) = client.send_record(&rec) {
                        error!("when sending record, an error occurred:{}", err);
                        control_l.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                Err(_) => continue,
            }
        })
        .unwrap();
    let _ = record_send.join();
    let _ = record_recv.join();
    info!("plugin will exit");
    Ok(())
}
