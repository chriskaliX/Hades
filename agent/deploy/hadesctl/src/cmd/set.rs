use anyhow::{bail, Result};
use clap::Args;

#[derive(Args)]
pub struct SetArgs {
    /// Service manager type: "systemd" or "sysvinit"
    #[arg(long = "service_type")]
    pub service_type: Option<String>,
    /// Override agent UUID
    #[arg(long = "id")]
    pub id: Option<String>,
}

pub fn run(args: SetArgs) -> Result<()> {
    if args.service_type.is_none() && args.id.is_none() {
        bail!("at least one flag required: --service_type or --id");
    }
    if let Some(ref stype) = args.service_type {
        if stype != "systemd" && stype != "sysvinit" {
            bail!("--service_type must be 'systemd' or 'sysvinit', got '{stype}'");
        }
        crate::config::set("service_type", stype)?;
    }
    if let Some(ref id) = args.id {
        crate::config::set("specified_id", id)?;
    }
    Ok(())
}
