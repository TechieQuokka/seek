use crate::cli::args::{ReportArgs, ReportType, OutputFormat};
use crate::cli::output::OutputFormatter;
use crate::data::models::config::AppConfig;
use crate::error::Result;
use crate::services::report_service::ReportService;
use std::fs;

pub async fn execute(args: ReportArgs, config: &AppConfig) -> Result<()> {
    let report_service = ReportService::new(config.clone())?;

    OutputFormatter::print_info("Generating report...");

    // 리포트 생성
    let report_content = report_service.generate_report(args.clone()).await?;

    // 출력 형식에 따라 처리
    match args.format {
        OutputFormat::Table => {
            // 이미 포맷된 텍스트 출력
            println!("{}", report_content);
        }
        OutputFormat::Json => {
            // JSON 형식으로 변환 (단순화)
            let json_report = serde_json::json!({
                "report_type": format!("{:?}", args.report_type.clone().unwrap_or(ReportType::System)),
                "period": format!("{:?}", args.period.clone().unwrap_or(crate::cli::args::Period::Week)),
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "content": report_content,
                "filter": args.filter
            });
            println!("{}", serde_json::to_string_pretty(&json_report)?);
        }
        OutputFormat::Csv => {
            // CSV는 간단한 형태로 제공
            OutputFormatter::print_warning("CSV format is limited for reports. Use --format table for better readability.");

            // 스캔 히스토리를 CSV 형식으로 출력
            if let Some(ReportType::Scan) = args.report_type {
                let days = match args.period.clone().unwrap_or(crate::cli::args::Period::Week) {
                    crate::cli::args::Period::Day => 1,
                    crate::cli::args::Period::Week => 7,
                    crate::cli::args::Period::Month => 30,
                    crate::cli::args::Period::Year => 365,
                };

                let history = report_service.get_scan_history(days, args.filter.as_deref()).await?;

                println!("timestamp,scan_type,target_path,files_scanned,threats_found,duration_seconds,status");
                for report in history {
                    let date = chrono::DateTime::from_timestamp(report.timestamp as i64, 0)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_else(|| "unknown".to_string());

                    println!("{},{},{},{},{},{},{}",
                        date,
                        report.scan_type,
                        report.target_path.display(),
                        report.files_scanned,
                        report.threats_found,
                        report.duration_seconds,
                        report.status
                    );
                }
            } else {
                println!("{}", report_content);
            }
        }
        OutputFormat::Html => {
            // HTML 형식으로 변환
            let html_content = format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <title>Seek Antivirus Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .report-content {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
        pre {{ white-space: pre-wrap; }}
    </style>
</head>
<body>
    <h1>Seek Antivirus Report</h1>
    <div class="report-content">
        <pre>{}</pre>
    </div>
    <footer>
        <p>Generated at: {}</p>
    </footer>
</body>
</html>"#,
                html_escape::encode_text(&report_content),
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!("{}", html_content);
        }
    }

    // 파일 저장
    if let Some(output_path) = args.output {
        let final_content = match args.format {
            OutputFormat::Json => {
                let json_report = serde_json::json!({
                    "report_type": format!("{:?}", args.report_type.clone().unwrap_or(ReportType::System)),
                    "period": format!("{:?}", args.period.clone().unwrap_or(crate::cli::args::Period::Week)),
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "content": report_content,
                    "filter": args.filter
                });
                serde_json::to_string_pretty(&json_report)?
            }
            OutputFormat::Html => {
                format!(
                    r#"<!DOCTYPE html>
<html>
<head>
    <title>Seek Antivirus Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .report-content {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
        pre {{ white-space: pre-wrap; }}
    </style>
</head>
<body>
    <h1>Seek Antivirus Report</h1>
    <div class="report-content">
        <pre>{}</pre>
    </div>
    <footer>
        <p>Generated at: {}</p>
    </footer>
</body>
</html>"#,
                    html_escape::encode_text(&report_content),
                    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                )
            }
            _ => report_content,
        };

        fs::write(&output_path, final_content)?;
        OutputFormatter::print_success(&format!(
            "✅ Report saved to: {}",
            output_path.display()
        ));
    }

    // 추가 통계 정보 표시
    if matches!(args.format, OutputFormat::Table) {
        println!("\n📊 Additional Statistics:");

        let days = match args.period.unwrap_or(crate::cli::args::Period::Week) {
            crate::cli::args::Period::Day => 1,
            crate::cli::args::Period::Week => 7,
            crate::cli::args::Period::Month => 30,
            crate::cli::args::Period::Year => 365,
        };

        let threat_stats = report_service.get_threat_statistics(days).await?;
        println!("Unique threat names: {}", threat_stats.unique_threat_names);

        if !threat_stats.by_severity.is_empty() {
            let critical = threat_stats.by_severity.get("Critical").unwrap_or(&0);
            let high = threat_stats.by_severity.get("High").unwrap_or(&0);
            let _medium = threat_stats.by_severity.get("Medium").unwrap_or(&0);
            let _low = threat_stats.by_severity.get("Low").unwrap_or(&0);

            if *critical > 0 {
                OutputFormatter::print_error(&format!("🚨 Critical threats detected: {}", critical));
            } else if *high > 0 {
                OutputFormatter::print_warning(&format!("⚠️  High severity threats: {}", high));
            } else {
                OutputFormatter::print_success("✅ No critical or high severity threats detected");
            }
        }
    }

    Ok(())
}