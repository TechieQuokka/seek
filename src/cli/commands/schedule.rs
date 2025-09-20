use crate::cli::args::{ScheduleArgs, ScheduleCommands};
use crate::cli::output::OutputFormatter;
use crate::data::models::config::AppConfig;
use crate::error::Result;
use crate::services::schedule_service::{ScheduleService, ScheduleType};

pub async fn execute(args: ScheduleArgs, config: &AppConfig) -> Result<()> {
    let schedule_service = ScheduleService::new(config.clone())?;

    match args.command {
        ScheduleCommands::Add(add_args) => {
            OutputFormatter::print_info("Adding new scheduled scan...");

            match schedule_service.add_schedule(add_args).await {
                Ok(schedule_id) => {
                    OutputFormatter::print_success(&format!(
                        "✅ Scheduled scan created successfully with ID: {}",
                        &schedule_id[..8]
                    ));
                }
                Err(e) => {
                    OutputFormatter::print_error(&format!("Failed to create schedule: {}", e));
                    return Err(e);
                }
            }
        }

        ScheduleCommands::List => {
            OutputFormatter::print_info("Listing scheduled scans...");
            let schedules = schedule_service.list_schedules().await?;

            if schedules.is_empty() {
                OutputFormatter::print_info("No scheduled scans found");
                return Ok(());
            }

            println!("\n📅 Scheduled Scans:");
            println!("{:<10} {:<20} {:<30} {:<12} {:<8} {:<15} {:<10}",
                "ID", "Name", "Path", "Type", "Enabled", "Cron", "Runs");
            println!("{}", "-".repeat(110));

            for schedule in schedules {
                let schedule_type = match schedule.schedule_type {
                    ScheduleType::Daily => "Daily".to_string(),
                    ScheduleType::Weekly => "Weekly".to_string(),
                    ScheduleType::Monthly => "Monthly".to_string(),
                    ScheduleType::Custom => "Custom".to_string(),
                };

                println!("{:<10} {:<20} {:<30} {:<12} {:<8} {:<15} {:<10}",
                    &schedule.id[..8],
                    schedule.name.chars().take(18).collect::<String>(),
                    schedule.path.display().to_string().chars().take(28).collect::<String>(),
                    schedule_type,
                    if schedule.enabled { "✅" } else { "❌" },
                    schedule.cron_expression.chars().take(13).collect::<String>(),
                    schedule.run_count
                );
            }

            let stats = schedule_service.get_schedule_stats().await?;
            println!("\n📊 Statistics:");
            println!("Total schedules: {}", stats.total_schedules);
            println!("Active schedules: {}", stats.active_schedules);
            println!("Total runs: {}", stats.total_runs);
        }

        ScheduleCommands::Remove { schedule_id } => {
            OutputFormatter::print_info(&format!("Removing schedule: {}", schedule_id));

            match schedule_service.remove_schedule(&schedule_id).await {
                Ok(true) => {
                    OutputFormatter::print_success("✅ Schedule removed successfully");
                }
                Ok(false) => {
                    OutputFormatter::print_warning(&format!("Schedule '{}' not found", schedule_id));
                }
                Err(e) => {
                    OutputFormatter::print_error(&format!("Failed to remove schedule: {}", e));
                    return Err(e);
                }
            }
        }

        ScheduleCommands::Enable { schedule_id } => {
            OutputFormatter::print_info(&format!("Enabling schedule: {}", schedule_id));

            match schedule_service.enable_schedule(&schedule_id).await {
                Ok(true) => {
                    OutputFormatter::print_success("✅ Schedule enabled successfully");
                }
                Ok(false) => {
                    OutputFormatter::print_warning(&format!("Schedule '{}' not found", schedule_id));
                }
                Err(e) => {
                    OutputFormatter::print_error(&format!("Failed to enable schedule: {}", e));
                    return Err(e);
                }
            }
        }

        ScheduleCommands::Disable { schedule_id } => {
            OutputFormatter::print_info(&format!("Disabling schedule: {}", schedule_id));

            match schedule_service.disable_schedule(&schedule_id).await {
                Ok(true) => {
                    OutputFormatter::print_success("✅ Schedule disabled successfully");
                }
                Ok(false) => {
                    OutputFormatter::print_warning(&format!("Schedule '{}' not found", schedule_id));
                }
                Err(e) => {
                    OutputFormatter::print_error(&format!("Failed to disable schedule: {}", e));
                    return Err(e);
                }
            }
        }
    }

    Ok(())
}