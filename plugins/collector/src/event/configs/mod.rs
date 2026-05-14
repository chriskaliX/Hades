//! configs/ — mirrors Go's event/configs/ sub-package.

pub mod sshconfig;
pub mod sshdconfig;

use anyhow::Result;
use sdk::Client;

pub async fn run(client: &mut Client) -> Result<()> {
    sshconfig::run(client).await?;
    sshdconfig::run(client).await?;
    Ok(())
}
