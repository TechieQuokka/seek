use crate::cli::args::StatusArgs;
use crate::cli::output::OutputFormatter;
use crate::data::models::config::AppConfig;
use crate::error::Result;
use crate::services::status_service::{StatusService, StatusLevel, ProtectionLevel};

pub async fn execute(args: StatusArgs, config: &AppConfig) -> Result<()> {
    let status_service = StatusService::new(config.clone());

    if args.watch {
        OutputFormatter::print_info("Starting system status monitoring (Press Ctrl+C to stop)...");
        status_service.watch_system_status(5).await?;
        return Ok(());
    }

    OutputFormatter::print_info("Checking system status...");

    let system_status = status_service.get_system_status().await?;
    let health_issues = status_service.check_system_health().await?;

    if args.json {
        // JSON 형식 출력
        let json_output = serde_json::to_string_pretty(&system_status)?;
        println!("{}", json_output);
        return Ok(());
    }

    // 일반 형식 출력
    println!("\n🖥️  Seek Antivirus System Status");
    println!("{}", "=".repeat(50));

    // 전체 건강 점수
    let health_icon = match system_status.health_score {
        90..=100 => "🟢",
        70..=89 => "🟡",
        50..=69 => "🟠",
        _ => "🔴",
    };

    println!("\n{} Overall Health Score: {}/100", health_icon, system_status.health_score);

    let status_time = chrono::DateTime::from_timestamp(system_status.timestamp as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    println!("📅 Status Time: {}", status_time);

    // 보안 상태
    println!("\n🛡️  Security Status:");
    let protection_icon = match system_status.security_status.protection_level {
        ProtectionLevel::Maximum => "🟢 Maximum",
        ProtectionLevel::High => "🟢 High",
        ProtectionLevel::Medium => "🟡 Medium",
        ProtectionLevel::Low => "🟠 Low",
        ProtectionLevel::Minimal => "🔴 Minimal",
    };
    println!("  Protection Level: {}", protection_icon);
    println!("  Signature Version: {}", system_status.security_status.signature_version);
    println!("  Active Monitors: {}", system_status.security_status.active_monitors);
    println!("  Quarantined Files: {}", system_status.security_status.quarantined_files);

    if system_status.security_status.threats_detected_today > 0 {
        println!("  ⚠️  Threats Today: {}", system_status.security_status.threats_detected_today);
    } else {
        println!("  ✅ No threats detected today");
    }

    // 엔진 상태
    println!("\n⚙️  Engine Status:");
    print_component_status("Signature Engine", &system_status.engine_status.signature_engine);
    print_component_status("Heuristic Engine", &system_status.engine_status.heuristic_engine);
    print_component_status("Quarantine Engine", &system_status.engine_status.quarantine_engine);
    print_component_status("Monitor Engine", &system_status.engine_status.monitor_engine);

    // 서비스 상태
    println!("\n📡 Services Status:");
    print_service_status("Monitor Service", &system_status.services_status.monitor_service);
    print_service_status("Update Service", &system_status.services_status.update_service);
    print_service_status("Schedule Service", &system_status.services_status.schedule_service);
    print_service_status("Report Service", &system_status.services_status.report_service);

    // 데이터베이스 상태
    println!("\n💾 Database Status:");
    print_database_status("Signatures DB", &system_status.database_status.signatures_db);
    print_database_status("Quarantine DB", &system_status.database_status.quarantine_db);
    print_database_status("Reports DB", &system_status.database_status.reports_db);
    print_database_status("Schedules DB", &system_status.database_status.schedules_db);

    // 설정 파일 상태
    println!("\n📄 Configuration:");
    let config_icon = if system_status.database_status.config_files.main_config { "✅" } else { "❌" };
    println!("  Main Config: {}", config_icon);

    let permissions_icon = if system_status.database_status.config_files.permissions_ok { "✅" } else { "❌" };
    println!("  Permissions: {}", permissions_icon);

    // 성능 메트릭
    println!("\n📊 Performance:");
    let uptime_hours = system_status.performance_metrics.uptime_seconds as f64 / 3600.0;
    println!("  Uptime: {:.1} hours", uptime_hours);

    if let Some(cpu) = system_status.performance_metrics.cpu_usage {
        let cpu_icon = if cpu > 80.0 { "🔴" } else if cpu > 50.0 { "🟡" } else { "🟢" };
        println!("  {} CPU Usage: {:.1}%", cpu_icon, cpu);
    }

    if let Some(memory) = system_status.performance_metrics.memory_usage {
        let memory_mb = memory as f64 / (1024.0 * 1024.0);
        println!("  Memory Usage: {:.1} MB", memory_mb);
    }

    // 디스크 사용량
    let disk = &system_status.performance_metrics.disk_usage;
    let used_percent = (disk.used_bytes as f64 / disk.total_bytes as f64) * 100.0;
    let disk_icon = if used_percent > 90.0 { "🔴" } else if used_percent > 75.0 { "🟡" } else { "🟢" };
    println!("  {} Disk Usage: {:.1}% ({:.1} GB / {:.1} GB)",
        disk_icon,
        used_percent,
        disk.used_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
        disk.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    );

    // 건강 이슈
    if !health_issues.is_empty() {
        println!("\n⚠️  Health Issues:");
        for issue in health_issues {
            if issue.contains("critical") || issue.contains("Critical") {
                OutputFormatter::print_error(&format!("  🚨 {}", issue));
            } else {
                OutputFormatter::print_warning(&format!("  ⚠️  {}", issue));
            }
        }
    } else {
        OutputFormatter::print_success("\n✅ No health issues detected");
    }

    // 권장 사항
    println!("\n💡 Recommendations:");
    if system_status.health_score < 80 {
        println!("  • Consider reviewing system configuration");
    }
    if system_status.security_status.active_monitors == 0 {
        println!("  • Enable real-time monitoring for better protection");
    }
    if matches!(system_status.security_status.protection_level, ProtectionLevel::Low | ProtectionLevel::Minimal) {
        println!("  • Enable signature and heuristic scanning for better protection");
    }
    if !system_status.database_status.signatures_db.exists {
        println!("  • Run 'seek update --download' to download signature database");
    }

    Ok(())
}

fn print_component_status(name: &str, component: &crate::services::status_service::ComponentStatus) {
    let icon = match component.status {
        StatusLevel::Healthy => "🟢",
        StatusLevel::Warning => "🟡",
        StatusLevel::Critical => "🔴",
        StatusLevel::Unknown => "⚪",
    };

    let version_str = component.version.as_ref()
        .map(|v| format!(" (v{})", v))
        .unwrap_or_default();

    println!("  {} {}{}", icon, name, version_str);

    for warning in &component.warnings {
        println!("    ⚠️  {}", warning);
    }

    for error in &component.errors {
        println!("    🚨 {}", error);
    }
}

fn print_service_status(name: &str, service: &crate::services::status_service::ServiceStatus) {
    let running_icon = if service.running { "🟢" } else { "🔴" };
    let status_icon = match service.status {
        StatusLevel::Healthy => "🟢",
        StatusLevel::Warning => "🟡",
        StatusLevel::Critical => "🔴",
        StatusLevel::Unknown => "⚪",
    };

    println!("  {} {} {} - {}", running_icon, status_icon, name, service.details);
}

fn print_database_status(name: &str, db: &crate::services::status_service::DatabaseInfo) {
    let exists_icon = if db.exists { "🟢" } else { "🔴" };
    let health_icon = match db.health {
        StatusLevel::Healthy => "🟢",
        StatusLevel::Warning => "🟡",
        StatusLevel::Critical => "🔴",
        StatusLevel::Unknown => "⚪",
    };

    let size_str = if db.exists {
        let size_mb = db.size_bytes as f64 / (1024.0 * 1024.0);
        format!(" ({:.1} MB)", size_mb)
    } else {
        String::new()
    };

    println!("  {} {} {}{}", exists_icon, health_icon, name, size_str);
}