use anyhow::Result;
use log::LevelFilter;
use sdk::{logger::{Config, Logger}, Client};
use std::path::PathBuf;

mod cache;
mod event;
mod manager;

#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(feature = "debug")]
    let client = Client::new(false);
    #[cfg(not(feature = "debug"))]
    let client = Client::new(true);

    log::set_boxed_logger(Box::new(Logger::new(Config {
        max_size:     1024 * 1024 * 5,
        path:         PathBuf::from("./collector.log"),
        #[cfg(not(feature = "debug"))]
        file_level:   LevelFilter::Info,
        #[cfg(feature = "debug")]
        file_level:   LevelFilter::Debug,
        remote_level: LevelFilter::Error,
        max_backups:  10,
        compress:     true,
        client:       Some(client.clone()),
    })))?;
    log::set_max_level(LevelFilter::Debug);

    let mut em = manager::EventManager::new();
    event::register(&mut em);
    em.schedule(client).await;
    Ok(())
}
