use std::sync::{Arc, Mutex};

use crossbeam::channel::Sender;
use lazy_static::lazy_static;
use sdk::Record;

lazy_static! {
    pub static ref TX: Arc<Mutex<Option<Sender<Record>>>> = Arc::new(Mutex::new(None));
}
