use crate::cli::args::OutputFormat;
use crate::data::models::{scan_result::ScanResult, threat::Threat};
use crate::error::Result;
use colored::*;
use tabled::{settings::Style, Table, Tabled};

pub struct OutputFormatter;

impl OutputFormatter {
    pub fn format_scan_result(result: &ScanResult, format: &OutputFormat) -> Result<String> {
        match format {
            OutputFormat::Table => Self::format_scan_result_table(result),
            OutputFormat::Json => Self::format_scan_result_json(result),
            OutputFormat::Csv => Self::format_scan_result_csv(result),
            OutputFormat::Html => Self::format_scan_result_html(result),
        }
    }

    pub fn format_threats(threats: &[Threat], format: &OutputFormat) -> Result<String> {
        match format {
            OutputFormat::Table => Self::format_threats_table(threats),
            OutputFormat::Json => Self::format_threats_json(threats),
            OutputFormat::Csv => Self::format_threats_csv(threats),
            OutputFormat::Html => Self::format_threats_html(threats),
        }
    }

    fn format_scan_result_table(result: &ScanResult) -> Result<String> {
        let mut output = String::new();

        // 스캔 결과 헤더
        output.push_str(&format!(
            "{}\\n",
            "┌─────────────────────────────────────────────────────────────┐".blue()
        ));
        output.push_str(&format!(
            "{}\\n",
            "│                        Scan Results                         │".blue().bold()
        ));
        output.push_str(&format!(
            "{}\\n",
            "├─────────────────────────────────────────────────────────────┤".blue()
        ));

        // 기본 정보
        output.push_str(&format!(
            "│ Scan ID: {}{}│\\n",
            result.id.cyan(),
            " ".repeat(45 - result.id.len())
        ));
        output.push_str(&format!(
            "│ Type: {}{}│\\n",
            result.scan_type.to_string().cyan(),
            " ".repeat(54 - result.scan_type.to_string().len())
        ));
        output.push_str(&format!(
            "│ Status: {}{}│\\n",
            match result.status {
                crate::data::models::scan_result::ScanStatus::Completed => "COMPLETED".green(),
                crate::data::models::scan_result::ScanStatus::Running => "RUNNING".yellow(),
                crate::data::models::scan_result::ScanStatus::Failed => "FAILED".red(),
                crate::data::models::scan_result::ScanStatus::Cancelled => "CANCELLED".yellow(),
                crate::data::models::scan_result::ScanStatus::Paused => "PAUSED".yellow(),
            },
            " ".repeat(52 - result.status.to_string().len())
        ));

        if let Some(duration) = &result.duration {
            output.push_str(&format!(
                "│ Duration: {}{}│\\n",
                format!("{:.2}s", duration.as_secs_f64()).cyan(),
                " ".repeat(50 - format!("{:.2}s", duration.as_secs_f64()).len())
            ));
        }

        output.push_str(&format!(
            "{}\\n",
            "├─────────────────────────────────────────────────────────────┤".blue()
        ));

        // 요약 정보
        let summary = &result.summary;
        output.push_str(&format!(
            "│ Files Scanned: {}{}│\\n",
            summary.files_scanned.to_string().cyan(),
            " ".repeat(46 - summary.files_scanned.to_string().len())
        ));

        let threats_color = if summary.threats_found > 0 {
            summary.threats_found.to_string().red()
        } else {
            summary.threats_found.to_string().green()
        };
        output.push_str(&format!(
            "│ Threats Found: {}{}│\\n",
            threats_color,
            " ".repeat(46 - summary.threats_found.to_string().len())
        ));

        output.push_str(&format!(
            "│ Quarantined: {}{}│\\n",
            summary.threats_quarantined.to_string().yellow(),
            " ".repeat(48 - summary.threats_quarantined.to_string().len())
        ));
        output.push_str(&format!(
            "│ Errors: {}{}│\\n",
            summary.errors_encountered.to_string().red(),
            " ".repeat(52 - summary.errors_encountered.to_string().len())
        ));

        output.push_str(&format!(
            "{}\\n",
            "└─────────────────────────────────────────────────────────────┘".blue()
        ));

        // 위협 목록
        if !result.threats.is_empty() {
            output.push_str("\\n");
            output.push_str(&Self::format_threats_table(&result.threats)?);
        }

        Ok(output)
    }

    fn format_threats_table(threats: &[Threat]) -> Result<String> {
        if threats.is_empty() {
            return Ok("No threats found.".green().to_string());
        }

        #[derive(Tabled)]
        struct ThreatDisplay {
            #[tabled(rename = "File")]
            file: String,
            #[tabled(rename = "Threat")]
            threat: String,
            #[tabled(rename = "Type")]
            threat_type: String,
            #[tabled(rename = "Severity")]
            severity: String,
            #[tabled(rename = "Action")]
            action: String,
        }

        let threat_displays: Vec<ThreatDisplay> = threats
            .iter()
            .map(|threat| ThreatDisplay {
                file: threat
                    .file_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                threat: threat.name.clone(),
                threat_type: threat.threat_type.to_string(),
                severity: threat.severity.to_string(),
                action: format!("{:?}", threat.action_taken),
            })
            .collect();

        let table = Table::new(threat_displays)
            .with(Style::rounded())
            .to_string();

        Ok(format!("{}\\n{}", "🦠 Detected Threats:".red().bold(), table))
    }

    fn format_scan_result_json(result: &ScanResult) -> Result<String> {
        serde_json::to_string_pretty(result).map_err(|e| e.into())
    }

    fn format_threats_json(threats: &[Threat]) -> Result<String> {
        serde_json::to_string_pretty(threats).map_err(|e| e.into())
    }

    fn format_scan_result_csv(_result: &ScanResult) -> Result<String> {
        // CSV 형식 구현
        Ok("CSV format not implemented yet".to_string())
    }

    fn format_threats_csv(_threats: &[Threat]) -> Result<String> {
        // CSV 형식 구현
        Ok("CSV format not implemented yet".to_string())
    }

    fn format_scan_result_html(_result: &ScanResult) -> Result<String> {
        // HTML 형식 구현
        Ok("HTML format not implemented yet".to_string())
    }

    fn format_threats_html(_threats: &[Threat]) -> Result<String> {
        // HTML 형식 구현
        Ok("HTML format not implemented yet".to_string())
    }

    pub fn print_progress(current: u64, total: u64, file_name: &str) {
        let percentage = if total > 0 { (current * 100) / total } else { 0 };
        let bar_length = 50;
        let filled_length = (percentage * bar_length) / 100;

        let bar = "█".repeat(filled_length as usize) + &"░".repeat((bar_length - filled_length) as usize);

        print!(
            "\\r🔍 Scanning: {} [{bar}] {}% ({}/{} files) - {}",
            "Progress".cyan(),
            percentage,
            current,
            total,
            file_name.truncate_to_width(30)
        );

        use std::io::{self, Write};
        io::stdout().flush().unwrap();
    }

    pub fn print_success(message: &str) {
        println!("{} {}", "✅".green(), message.green());
    }

    pub fn print_warning(message: &str) {
        println!("{} {}", "⚠️".yellow(), message.yellow());
    }

    pub fn print_error(message: &str) {
        println!("{} {}", "❌".red(), message.red());
    }

    pub fn print_info(message: &str) {
        println!("{} {}", "ℹ️".blue(), message.blue());
    }
}

trait TruncateToWidth {
    fn truncate_to_width(&self, width: usize) -> String;
}

impl TruncateToWidth for str {
    fn truncate_to_width(&self, width: usize) -> String {
        if self.len() <= width {
            self.to_string()
        } else {
            format!("{}...", &self[..width.saturating_sub(3)])
        }
    }
}