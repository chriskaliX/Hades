use super::parser::{dns::DnsPolicy, tc::TcPolicy};
use serde::{Deserialize, Serialize};

#[cfg(feature = "debug")]
use anyhow::{anyhow, Error};
#[cfg(feature = "debug")]
use std::fs;

/// Config of the eguard, for now, only tc vec
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub tc: Vec<TcPolicy>,
    pub dns: Vec<DnsPolicy>,
}

impl Config {
    #[cfg(feature = "debug")]
    pub fn from_file(path: &str) -> Result<Self, Error> {
        let file = fs::read_to_string(path)?;
        let config: Config =
            serde_yaml::from_str(&file).map_err(|err| anyhow!("failed to parse YAML: {}", err))?;
        Ok(config)
    }
}
