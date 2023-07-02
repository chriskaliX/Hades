use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum EgressAction {
    DENY,
    LOG,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum EgressProtocol {
    ALL,
    TCP,
    UDP,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub egress: Vec<EgressPolicy>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct EgressPolicy {
    pub name: String,
    pub address: String,
    pub protocol: EgressProtocol,
    pub action: EgressAction,
    pub level: String,
}
