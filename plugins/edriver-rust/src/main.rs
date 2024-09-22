use anyhow::Result;
use edriver::*;
use log::*;
use sdk::{logger::*, Client};
use std::path::PathBuf;

fn main() -> Result<()> {
    // client init
    #[cfg(feature = "debug")]
    let client = Client::new(false);
    #[cfg(not(feature = "debug"))]
    let client = Client::new(true);
    // log init
    set_boxed_logger(Box::new(Logger::new(Config {
        max_size: 1024 * 1024 * 5,
        path: PathBuf::from("./edriver.log"),
        #[cfg(not(feature = "debug"))]
        file_level: LevelFilter::Info,
        #[cfg(feature = "debug")]
        file_level: LevelFilter::Debug,
        remote_level: LevelFilter::Error,
        max_backups: 10,
        compress: true,
        client: Some(client.clone()),
    })))?;

    bpfmgr::Bpfmanager::new(client)?;
    Ok(())
}
