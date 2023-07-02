use std::sync::Mutex;

use crossbeam::channel::Sender;
use lazy_static::lazy_static;
use sdk::Record;

lazy_static! {
    pub static ref TX: Mutex<Option<Sender<Record>>> = Mutex::new(None);
}
