// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use anyhow::{Result};
use event::tc::TcEvent;
use core::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;

mod manager;
mod event;

use crate::manager::manager::Bpfmanager;


fn main() -> Result<()> {
    // Install Ctrl-C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    Bpfmanager::bump_memlock_rlimit()?;
    let mut mgr = Bpfmanager::new();
    // tc egress restriction
    let mut event = TcEvent::new();
    event.set_if("eth0").unwrap(); // debug
    mgr.load_program("tc", Box::new(event));
    mgr.start_program("tc")?;

    // Block until SIGINT
    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0));
    }

    mgr.stop_program("tc")?;
    Ok(())
}