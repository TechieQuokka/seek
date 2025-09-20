use crate::cli::args::{ConfigArgs, ConfigCommands};
use crate::cli::output::OutputFormatter;
use crate::data::models::config::AppConfig;
use crate::error::Result;
use crate::services::config_service::ConfigService;

pub async fn execute(args: ConfigArgs, config: &AppConfig) -> Result<()> {
    // 현재 설정 파일 경로 추정 (실제로는 CLI에서 전달받아야 함)
    let config_path = config.signature.database_path.join("../config.toml");
    let config_service = ConfigService::new(config_path);

    match args.command {
        ConfigCommands::Show => {
            OutputFormatter::print_info("Current configuration:");

            let current_config = config_service.show_config().await?;

            println!("\n⚙️  Configuration Settings:");
            println!("{}", "=".repeat(50));

            // 스캔 설정
            println!("\n📊 Scan Settings:");
            println!("  max_threads: {}", current_config.scan.max_threads);
            println!("  max_file_size: {} bytes", current_config.scan.max_file_size);
            println!("  timeout: {}", current_config.scan.timeout);
            println!("  heuristic_enabled: {}", current_config.scan.heuristic_enabled);
            println!("  scan_archives: {}", current_config.scan.scan_archives);

            // 격리 설정
            println!("\n🔒 Quarantine Settings:");
            println!("  directory: {}", current_config.quarantine.directory.display());
            println!("  encrypt: {}", current_config.quarantine.encrypt);

            // 데이터 설정
            println!("\n💾 Data Settings:");
            println!("  database_path: {}", current_config.signature.database_path.display());

            // 모니터 설정
            println!("\n👁️  Monitor Settings:");
            println!("  enabled: {}", current_config.monitor.enabled);

            // 로깅 설정
            println!("\n📝 Logging Settings:");
            println!("  level: {}", current_config.logging.level);
            println!("  console_output: {}", current_config.logging.console_output);

            // 패턴 설정
            if !current_config.scan.exclude_patterns.is_empty() {
                println!("\n🚫 Exclude Patterns:");
                for pattern in &current_config.scan.exclude_patterns {
                    println!("  - {}", pattern);
                }
            }

            if !current_config.scan.include_patterns.is_empty() {
                println!("\n✅ Include Patterns:");
                for pattern in &current_config.scan.include_patterns {
                    println!("  - {}", pattern);
                }
            }
        }

        ConfigCommands::Set { key, value } => {
            OutputFormatter::print_info(&format!("Setting configuration: {} = {}", key, value));

            match config_service.set_config_value(&key, &value).await {
                Ok(_) => {
                    OutputFormatter::print_success("✅ Configuration updated successfully");

                    // 변경된 값 확인
                    match config_service.get_config_value(&key).await {
                        Ok(new_value) => {
                            println!("New value: {} = {}", key, new_value);
                        }
                        Err(e) => {
                            OutputFormatter::print_warning(&format!("Could not verify new value: {}", e));
                        }
                    }
                }
                Err(e) => {
                    OutputFormatter::print_error(&format!("Failed to update configuration: {}", e));
                    return Err(e);
                }
            }
        }

        ConfigCommands::Reset => {
            OutputFormatter::print_info("Resetting configuration to default values...");

            match config_service.reset_config().await {
                Ok(_) => {
                    OutputFormatter::print_success("✅ Configuration reset to default values");
                    OutputFormatter::print_info("A backup of the previous configuration has been created");
                }
                Err(e) => {
                    OutputFormatter::print_error(&format!("Failed to reset configuration: {}", e));
                    return Err(e);
                }
            }
        }

        ConfigCommands::Export { file } => {
            OutputFormatter::print_info(&format!("Exporting configuration to: {}", file.display()));

            match config_service.export_config(&file).await {
                Ok(_) => {
                    OutputFormatter::print_success("✅ Configuration exported successfully");
                }
                Err(e) => {
                    OutputFormatter::print_error(&format!("Failed to export configuration: {}", e));
                    return Err(e);
                }
            }
        }

        ConfigCommands::Import { file } => {
            OutputFormatter::print_info(&format!("Importing configuration from: {}", file.display()));

            match config_service.import_config(&file).await {
                Ok(_) => {
                    OutputFormatter::print_success("✅ Configuration imported successfully");
                    OutputFormatter::print_info("A backup of the previous configuration has been created");

                    // 설정 검증
                    OutputFormatter::print_info("Validating imported configuration...");
                    let issues = config_service.validate_current_config().await?;

                    if issues.is_empty() {
                        OutputFormatter::print_success("✅ Configuration validation passed");
                    } else {
                        OutputFormatter::print_warning("⚠️  Configuration validation found issues:");
                        for issue in issues {
                            println!("  - {}", issue);
                        }
                    }
                }
                Err(e) => {
                    OutputFormatter::print_error(&format!("Failed to import configuration: {}", e));

                    // 백업에서 복원 시도
                    OutputFormatter::print_info("Attempting to restore from backup...");
                    if config_service.restore_from_backup().await? {
                        OutputFormatter::print_success("✅ Configuration restored from backup");
                    } else {
                        OutputFormatter::print_error("❌ No backup available");
                    }

                    return Err(e);
                }
            }
        }
    }

    Ok(())
}