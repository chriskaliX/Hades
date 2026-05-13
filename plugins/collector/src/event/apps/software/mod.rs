pub mod go;
pub mod java;
pub mod php;
pub mod python;

use crate::event::apps::IApp;

pub fn apps() -> Vec<Box<dyn IApp>> {
    vec![
        Box::new(java::Java::new()),
        Box::new(python::Python::new()),
        Box::new(php::PHP::new()),
        Box::new(go::Golang::new()),
    ]
}
