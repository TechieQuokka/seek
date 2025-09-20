use crate::cli::args::UpdateArgs;
use crate::cli::output::OutputFormatter;
use crate::data::models::config::AppConfig;
use crate::error::Result;
use crate::services::update_service::UpdateService;

pub async fn execute(args: UpdateArgs, config: &AppConfig) -> Result<()> {
    let update_service = UpdateService::new(config.clone())?;

    if args.check {
        OutputFormatter::print_info("Checking for signature database updates...");

        match update_service.check_for_updates().await? {
            Some(update_info) => {
                println!("\n🔄 Update Available!");
                println!("Current version: {}", update_service.get_current_info().await?.version);
                println!("Latest version: {}", update_info.version);
                println!("New signatures: {}", update_info.signature_count);
                println!("Source: {}", update_info.source);

                let update_time = chrono::DateTime::from_timestamp(update_info.last_updated as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "Unknown".to_string());
                println!("Released: {}", update_time);

                OutputFormatter::print_info("Run with --download to install updates");
            }
            None => {
                let current_info = update_service.get_current_info().await?;
                OutputFormatter::print_success(&format!(
                    "✅ Signature database is up to date (version: {})",
                    current_info.version
                ));

                let (sig_count, last_updated) = update_service.get_signature_stats().await?;
                println!("Signatures: {}", sig_count);

                if last_updated > 0 {
                    let last_update_time = chrono::DateTime::from_timestamp(last_updated as i64, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "Unknown".to_string());
                    println!("Last updated: {}", last_update_time);
                }
            }
        }
        return Ok(());
    }

    if args.download {
        OutputFormatter::print_info("Downloading signature database updates...");

        let updated = update_service.download_updates(args.force).await?;

        if updated {
            OutputFormatter::print_success("✅ Signature database updated successfully");

            let (sig_count, _) = update_service.get_signature_stats().await?;
            println!("Total signatures: {}", sig_count);

            // 유효성 검사
            OutputFormatter::print_info("Validating signature database...");
            let is_valid = update_service.validate_database().await?;

            if is_valid {
                OutputFormatter::print_success("✅ Database validation passed");
            } else {
                OutputFormatter::print_error("❌ Database validation failed");

                // 백업에서 복원 시도
                OutputFormatter::print_info("Attempting to restore from backup...");
                let restored = update_service.restore_from_backup().await?;

                if restored {
                    OutputFormatter::print_success("✅ Database restored from backup");
                } else {
                    OutputFormatter::print_error("❌ No backup available");
                    return Err(crate::error::Error::Database(
                        "Database validation failed and no backup available".to_string()
                    ));
                }
            }
        } else {
            OutputFormatter::print_info("No updates were downloaded (already up to date)");
        }
        return Ok(());
    }

    // 기본 동작: 현재 상태 표시
    OutputFormatter::print_info("Current signature database status:");

    let current_info = update_service.get_current_info().await?;
    let (sig_count, last_updated) = update_service.get_signature_stats().await?;

    println!("\n📊 Database Information:");
    println!("Version: {}", current_info.version);
    println!("Signatures: {}", sig_count);
    println!("Source: {}", current_info.source);

    if last_updated > 0 {
        let last_update_time = chrono::DateTime::from_timestamp(last_updated as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Unknown".to_string());
        println!("Last updated: {}", last_update_time);
    }

    // 데이터베이스 유효성 검사
    OutputFormatter::print_info("\nValidating database...");
    let is_valid = update_service.validate_database().await?;

    if is_valid {
        OutputFormatter::print_success("✅ Database is valid");
    } else {
        OutputFormatter::print_error("❌ Database validation failed");
    }

    println!("\nUse --check to check for updates");
    println!("Use --download to download and install updates");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_update_execute() {
        let args = UpdateArgs {
            check: true,
            download: false,
            force: false,
            source: None,
        };
        let config = AppConfig::default();

        let result = execute(args, &config).await;
        assert!(result.is_ok());
    }
}