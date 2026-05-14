//! libraries/ — mirrors Go's event/libraries/ sub-package.

pub mod dpkg;
pub mod jar;
pub mod rpm;
pub mod yum;

use anyhow::Result;
use sdk::Client;

pub async fn run(client: &mut Client) -> Result<()> {
    dpkg::run(client).await?;
    rpm::run(client).await?;
    jar::run(client).await?;
    yum::run(client).await?;
    Ok(())
}
