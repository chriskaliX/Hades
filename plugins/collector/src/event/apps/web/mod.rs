pub mod apache;
pub mod jetty;
pub mod nginx;
pub mod openresty;
pub mod tengine;

use crate::event::apps::IApp;

pub fn apps() -> Vec<Box<dyn IApp>> {
    vec![
        Box::new(nginx::Nginx::new()),
        Box::new(apache::Apache2::new()),
        Box::new(openresty::Openresty::new()),
        Box::new(tengine::Tengine::new()),
        Box::new(jetty::Jetty::new()),
    ]
}
