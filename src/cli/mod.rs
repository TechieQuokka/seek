pub mod args;
pub mod commands;
pub mod output;

use crate::data::models::config::AppConfig;
use crate::error::Result;
pub use args::Args;

pub async fn run(args: Args, config: AppConfig) -> Result<()> {
    match args.command {
        Some(command) => match command {
            args::Commands::Scan(scan_args) => {
                commands::scan::execute(scan_args, &config).await
            }
            args::Commands::Monitor(monitor_args) => {
                commands::monitor::execute(monitor_args, &config).await
            }
            args::Commands::Quarantine(quarantine_args) => {
                commands::quarantine::execute(quarantine_args, &config).await
            }
            args::Commands::Update(update_args) => {
                commands::update::execute(update_args, &config).await
            }
            args::Commands::Schedule(schedule_args) => {
                commands::schedule::execute(schedule_args, &config).await
            }
            args::Commands::Config(config_args) => {
                commands::config::execute(config_args, &config).await
            }
            args::Commands::Report(report_args) => {
                commands::report::execute(report_args, &config).await
            }
            args::Commands::Status(status_args) => {
                commands::status::execute(status_args, &config).await
            }
        },
        None => {
            // 서브커맨드가 없으면 help 출력
            use clap::CommandFactory;
            let mut cmd = args::Args::command();
            cmd.print_help()?;
            Ok(())
        }
    }
}