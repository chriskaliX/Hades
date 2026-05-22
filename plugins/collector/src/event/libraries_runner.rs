/// Libraries IEvent wrapper — data_type 9999.
/// Dispatches to all library sub-collectors.
use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;

use crate::event::libraries as libraries_mod;
use crate::manager::{EventMode, IEvent};

pub struct Libraries;

#[async_trait]
impl IEvent for Libraries {
    fn name(&self)        -> &'static str { "libraries" }
    fn data_type(&self)   -> i32          { 9999 }
    fn flag(&self)        -> EventMode    { EventMode::Periodic }
    fn immediately(&self) -> bool         { false }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        libraries_mod::run(client).await
    }
}
