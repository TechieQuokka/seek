use crate::cli::args::{QuarantineArgs, QuarantineCommands};
use crate::cli::output::OutputFormatter;
use crate::data::models::config::AppConfig;
use crate::error::Result;
use crate::services::quarantine_service::QuarantineService;

pub async fn execute(args: QuarantineArgs, config: &AppConfig) -> Result<()> {
    let quarantine_service = QuarantineService::new(config.clone())?;

    match args.command {
        QuarantineCommands::List => {
            OutputFormatter::print_info("Listing quarantined files...");
            let files = quarantine_service.list_quarantined_files().await?;

            if files.is_empty() {
                OutputFormatter::print_info("No files currently in quarantine");
                return Ok(());
            }

            println!("\n📦 Quarantined Files:");
            println!("{:<36} {:<30} {:<15} {:<20} {:<15}",
                "ID", "Original Path", "Size (bytes)", "Quarantine Time", "Threat Type");
            println!("{}", "-".repeat(120));

            for file in files {
                let quarantine_time = chrono::DateTime::from_timestamp(file.quarantine_time as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "Unknown".to_string());

                println!("{:<36} {:<30} {:<15} {:<20} {:<15}",
                    &file.id[..8], // 처음 8자리만 표시
                    file.original_path.display().to_string().chars().take(28).collect::<String>(),
                    file.file_size,
                    quarantine_time,
                    file.threat_info.threat_type
                );
            }

            let stats = quarantine_service.get_quarantine_stats().await?;
            println!("\n📊 Statistics:");
            println!("Total files: {}", stats.total_files);
            println!("Total size: {} bytes", stats.total_size);
        }

        QuarantineCommands::Restore { file_id } => {
            OutputFormatter::print_info(&format!("Restoring file: {}", file_id));

            match quarantine_service.restore_file(&file_id).await {
                Ok(restored_path) => {
                    OutputFormatter::print_success(&format!(
                        "File restored successfully to: {}",
                        restored_path.display()
                    ));
                }
                Err(e) => {
                    OutputFormatter::print_error(&format!("Failed to restore file: {}", e));
                    return Err(e);
                }
            }
        }

        QuarantineCommands::Delete { file_id } => {
            OutputFormatter::print_info(&format!("Permanently deleting quarantined file: {}", file_id));

            match quarantine_service.delete_quarantined_file(&file_id).await {
                Ok(_) => {
                    OutputFormatter::print_success("File deleted permanently from quarantine");
                }
                Err(e) => {
                    OutputFormatter::print_error(&format!("Failed to delete file: {}", e));
                    return Err(e);
                }
            }
        }

        QuarantineCommands::Info { file_id } => {
            OutputFormatter::print_info(&format!("Getting information for file: {}", file_id));

            match quarantine_service.get_quarantined_file(&file_id).await {
                Ok(file) => {
                    println!("\n🔍 Quarantined File Information:");
                    println!("ID: {}", file.id);
                    println!("Original Path: {}", file.original_path.display());
                    println!("Quarantine Path: {}", file.quarantine_path.display());
                    println!("File Name: {}", file.file_name);
                    println!("File Size: {} bytes", file.file_size);
                    println!("SHA256 Hash: {}", file.sha256_hash);

                    let quarantine_time = chrono::DateTime::from_timestamp(file.quarantine_time as i64, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "Unknown".to_string());
                    println!("Quarantined: {}", quarantine_time);

                    println!("\n🦠 Threat Information:");
                    println!("Name: {}", file.threat_info.name);
                    println!("Type: {}", file.threat_info.threat_type);
                    println!("Severity: {:?}", file.threat_info.severity);
                    println!("Detection Method: {}", file.threat_info.detection_method);
                    // Risk score not available in current threat model

                    if let Some(description) = &file.threat_info.description {
                        println!("Description: {}", description);
                    }
                }
                Err(e) => {
                    OutputFormatter::print_error(&format!("Failed to get file information: {}", e));
                    return Err(e);
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
    async fn test_quarantine_execute() {
        use crate::cli::args::QuarantineCommands;

        let args = QuarantineArgs {
            command: QuarantineCommands::List,
        };
        let config = AppConfig::default();

        let result = execute(args, &config).await;
        assert!(result.is_ok());
    }
}