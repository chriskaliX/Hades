use clap::{Parser, Subcommand};

mod cmd;
mod config;

#[derive(Parser)]
#[command(name = "hadesctl", about = "Control tool for hades-agent")]
#[command(disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Set agent environment variables (--service_type / --id)
    Set(cmd::set::SetArgs),
    /// Enable agent auto-start (systemd or sysvinit)
    Enable,
    /// Disable agent auto-start
    Disable,
    /// Start agent
    Start,
    /// Stop agent
    Stop,
    /// Restart agent
    Restart,
    /// Show agent status
    Status,
    /// Reload service manager configuration
    #[command(name = "service-reload")]
    ServiceReload,
    /// Watchdog check for sysvinit: start agent if it is dead
    Check,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Set(args)   => cmd::set::run(args),
        Commands::Enable      => cmd::enable::run(),
        Commands::Disable     => cmd::disable::run(),
        Commands::Start       => cmd::start::run(),
        Commands::Stop        => cmd::stop::run(),
        Commands::Restart     => cmd::restart::run(),
        Commands::Status      => cmd::status::run(),
        Commands::ServiceReload => cmd::reload::run(),
        Commands::Check       => cmd::check::run(),
    };
    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
