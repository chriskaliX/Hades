/// Configs IEvent wrapper — data_type 9998.
/// Dispatches to all configs sub-collectors.
use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;

use crate::event::configs as configs_mod;
use crate::manager::{EventMode, IEvent};

pub struct Configs;

#[async_trait]
impl IEvent for Configs {
    fn name(&self)        -> &'static str { "configs" }
    fn data_type(&self)   -> i32          { 9998 }
    fn flag(&self)        -> EventMode    { EventMode::Periodic }
    fn immediately(&self) -> bool         { false }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        configs_mod::run(client).await
    }
}
