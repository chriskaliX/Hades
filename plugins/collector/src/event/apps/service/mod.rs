pub mod nscd;
pub mod ntp;

use crate::event::apps::IApp;

pub fn apps() -> Vec<Box<dyn IApp>> {
    vec![
        Box::new(nscd::Nscd::new()),
        Box::new(ntp::Ntp::new()),
    ]
}
