use crate::cli::args::{MonitorArgs, MonitorCommands};
use crate::cli::output::OutputFormatter;
use crate::data::models::config::AppConfig;
use crate::error::Result;
use crate::services::monitor_service::MonitorService;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn expand_tilde_path(path: &Path) -> PathBuf {
    if let Some(path_str) = path.to_str() {
        if path_str.starts_with("~/") || path_str == "~" {
            if let Ok(home_dir) = std::env::var("HOME") {
                // Unix-like systems
                PathBuf::from(path_str.replacen("~", &home_dir, 1))
            } else if let Ok(home_dir) = std::env::var("USERPROFILE") {
                // Windows systems
                PathBuf::from(path_str.replacen("~", &home_dir, 1))
            } else {
                // Fallback to original path if no home directory found
                path.to_path_buf()
            }
        } else {
            path.to_path_buf()
        }
    } else {
        path.to_path_buf()
    }
}

pub async fn execute(args: MonitorArgs, config: &AppConfig) -> Result<()> {
    let monitor_service = MonitorService::new(Arc::new(config.clone()));

    match args.command {
        MonitorCommands::Start(start_args) => {
            OutputFormatter::print_info("Starting real-time monitoring...");

            let target_path = if let Some(path) = start_args.path.clone() {
                expand_tilde_path(&path)
            } else {
                std::env::current_dir().unwrap_or_default()
            };

            if start_args.daemon {
                OutputFormatter::print_info("Starting monitor in daemon mode...");

                // 데몬 모드로 백그라운드 실행
                let config_arc = std::sync::Arc::new(config.clone());
                let target_path_clone = target_path.clone();
                let start_args_clone = start_args.clone();

                match tokio::task::spawn(async move {
                    let monitor_service_daemon = MonitorService::new(config_arc);
                    monitor_service_daemon.start_monitoring(target_path_clone, start_args_clone).await
                }).await {
                    Ok(Ok(_)) => {
                        OutputFormatter::print_success("✅ Monitor daemon started successfully");
                        OutputFormatter::print_info("Use 'seek monitor stop' to stop the daemon");
                        return Ok(());
                    }
                    Ok(Err(e)) => {
                        OutputFormatter::print_error(&format!("❌ Failed to start daemon: {}", e));
                        return Err(e);
                    }
                    Err(e) => {
                        OutputFormatter::print_error(&format!("❌ Daemon task failed: {}", e));
                        return Err(crate::error::Error::Other(e.to_string()));
                    }
                }
            }

            OutputFormatter::print_info(&format!("Monitoring path: {}", target_path.display()));
            OutputFormatter::print_info("Press Ctrl+C to stop monitoring");

            // 모니터링 시작
            monitor_service.start_monitoring(target_path, start_args).await?;
        }

        MonitorCommands::Stop => {
            OutputFormatter::print_info("Stopping real-time monitoring...");
            monitor_service.stop_monitoring().await?;
            OutputFormatter::print_success("Monitoring stopped successfully");
        }

        MonitorCommands::Status => {
            OutputFormatter::print_info("Checking monitoring status...");
            let is_active = monitor_service.is_monitoring_active().await?;

            if is_active {
                OutputFormatter::print_success("✅ Real-time monitoring is ACTIVE");
            } else {
                OutputFormatter::print_info("❌ Real-time monitoring is INACTIVE");
            }
        }

        MonitorCommands::Logs(log_args) => {
            OutputFormatter::print_info(&format!("Showing last {} log entries...", log_args.lines));

            if log_args.follow {
                OutputFormatter::print_info("Following logs in real-time (Press Ctrl+C to stop):");
                monitor_service.follow_logs().await?;
            } else {
                let logs = monitor_service.get_recent_logs(log_args.lines).await?;
                for log_entry in logs {
                    println!("{}", log_entry);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_monitor_execute() {
        use crate::cli::args::MonitorCommands;

        let args = MonitorArgs {
            command: MonitorCommands::Status,
        };
        let config = AppConfig::default();

        let result = execute(args, &config).await;
        assert!(result.is_ok());
    }
}