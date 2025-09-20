use crate::cli::args::ScheduleArgs;
use crate::data::models::config::AppConfig;
use crate::error::Result;

pub async fn execute(args: ScheduleArgs, _config: &AppConfig) -> Result<()> {
    println!("Schedule command not yet implemented: {:?}", args);
    Ok(())
}