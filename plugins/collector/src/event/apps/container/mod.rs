pub mod containerd;
pub mod docker;
pub mod kubeapiserver;
pub mod kubelet;

use crate::event::apps::IApp;

pub fn apps() -> Vec<Box<dyn IApp>> {
    vec![
        Box::new(docker::Docker::new()),
        Box::new(containerd::Containerd::new()),
        Box::new(kubelet::Kubelet::new()),
        Box::new(kubeapiserver::KubeApiserver::new()),
    ]
}
