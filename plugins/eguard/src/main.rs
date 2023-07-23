// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use crossbeam::channel::bounded;
use log::*;
use log::set_boxed_logger;
use sdk::{logger::*, Client};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use event::egress::TcEvent;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

mod config;
mod event;
mod manager;

use crate::config::config::Config as BpfConfig;
use crate::event::egress::EVENT_EGRESS;
use crate::manager::manager::Bpfmanager;

fn main() {
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
    }))).unwrap();
    
    // Install Ctrl-C handler
    let control_s = Arc::new(AtomicBool::new(false));
    let control_l = control_s.clone();
    let control_c = control_s.clone();
    ctrlc::set_handler(move || {
        control_c.store(true, Ordering::Relaxed);
    }).unwrap();

    // set channel and replace
    let (tx, rx) = bounded(512);
    {
        let mut lock = event::event::TX.lock()
            .map_err(|e| error!("failed to define shared notification sender: {}", e))
            .unwrap();
        *lock = Some(tx);
    }

    // tc egress restriction
    Bpfmanager::bump_memlock_rlimit().unwrap();
    let mgr: Arc<Mutex<Bpfmanager>> = Mutex::new(Bpfmanager::new()).into();
    let event = TcEvent::new();
    mgr.lock().unwrap().load_program(EVENT_EGRESS, Box::new(event));
    if let Err(e) = mgr.lock().unwrap().start_program(EVENT_EGRESS) {
        error!("start tc failed: {}", e);
        return;
    }
    info!("init bpf program successfully");
    // task_receive thread
    let mut client_c = client.clone();
    let mgr_c = mgr.clone();
    let _ = thread::Builder::new()
        .name("task_receive".to_owned())
        .spawn(move || loop {
            match client_c.receive() {
                Ok(task) => {
                    // handle task
                    match serde_json::from_str::<BpfConfig>(task.get_data()) {
                        Ok(config) => {
                            if let Err(e) = mgr_c.lock().unwrap().flush_config(config) {
                                error!("parse task failed: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("parse task failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("when receiving task, an error occurred: {}", e);
                    control_s.store(true, Ordering::Relaxed);
                    return;
                }
            }
        });
    info!("task receive handler is running");
    let timeout = Duration::from_millis(500);
    // record_send thread
    let record_send = thread::Builder::new()
        .name("record_send".to_string())
        .spawn(move || loop {
            if control_l.load(Ordering::Relaxed) {
                break;
            }

            let rec = rx.recv_timeout(timeout);
            match rec {
                Ok(rec) => {
                    if let Err(err) = client.send_record(&rec) {
                        error!("when sending record, an error occurred:{}", err);
                        return;
                    }
                }
                Err(_) => continue
            }
        }).unwrap();
    let _ = record_send.join();
    info!("record_send is exiting");
    mgr.lock().unwrap().stop_program(EVENT_EGRESS);
    info!("plugin will exit");
}
