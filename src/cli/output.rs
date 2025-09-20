use crate::cli::args::OutputFormat;
use crate::data::models::{scan_result::ScanResult, threat::Threat};
use crate::error::Result;
use colored::*;
use unicode_width::{UnicodeWidthStr, UnicodeWidthChar};

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
        // 표시할 데이터 준비
        let scan_id = &result.id;
        let scan_type = result.scan_type.to_string();
        let status_text = result.status.to_string();
        let duration_text = result.duration
            .map(|d| format!("{:.2}s", d.as_secs_f64()))
            .unwrap_or_else(|| "N/A".to_string());

        let files_scanned = result.summary.files_scanned.to_string();
        let threats_found = result.summary.threats_found.to_string();
        let quarantined = result.summary.threats_quarantined.to_string();
        let errors = result.summary.errors_encountered.to_string();

        // 각 필드의 최대 길이 계산
        let data_rows = [
            ("Scan ID:", scan_id),
            ("Type:", &scan_type),
            ("Status:", &status_text),
            ("Duration:", &duration_text),
            ("Files Scanned:", &files_scanned),
            ("Threats Found:", &threats_found),
            ("Quarantined:", &quarantined),
            ("Errors:", &errors),
        ];

        // 라벨 열의 적정 너비 설정 (너무 긴 라벨로 인한 과도한 공백 방지)
        let label_column_width = 15; // 고정 너비로 설정

        let max_value_width = data_rows.iter()
            .map(|(_, value)| value.width())
            .max()
            .unwrap_or(0);

        let table_width = label_column_width + max_value_width + 4; // 라벨열 + 값열 + 패딩
        let table_width = table_width.max(50); // 최소 너비 보장

        let mut output = String::new();

        // 상단 경계선
        let top_border = "┌".to_string() + &"─".repeat(table_width) + "┐";
        output.push_str(&format!("{}\n", top_border.blue()));

        // 제목
        let title = "Scan Results";
        let title_padding = (table_width.saturating_sub(title.width())) / 2;
        let title_line = format!("│{}{}{}│",
            " ".repeat(title_padding),
            title,
            " ".repeat(table_width - title_padding - title.width()));
        output.push_str(&format!("{}\n", title_line.blue().bold()));

        // 제목 구분선
        let title_separator = "├".to_string() + &"─".repeat(table_width) + "┤";
        output.push_str(&format!("{}\n", title_separator.blue()));

        // 데이터 행들
        for (i, (label, value)) in data_rows.iter().enumerate() {
            let colored_value = match *label {
                "Status:" => match result.status {
                    crate::data::models::scan_result::ScanStatus::Completed => value.green().to_string(),
                    crate::data::models::scan_result::ScanStatus::Running => value.yellow().to_string(),
                    crate::data::models::scan_result::ScanStatus::Failed => value.red().to_string(),
                    crate::data::models::scan_result::ScanStatus::Cancelled => value.yellow().to_string(),
                    crate::data::models::scan_result::ScanStatus::Paused => value.yellow().to_string(),
                },
                "Threats Found:" => {
                    if result.summary.threats_found > 0 {
                        value.red().to_string()
                    } else {
                        value.green().to_string()
                    }
                },
                "Quarantined:" => value.yellow().to_string(),
                "Errors:" => value.red().to_string(),
                _ => value.cyan().to_string(),
            };

            // 적정한 패딩 계산
            // 패턴: │ Label:     Value                        │
            let label_width = label.width();
            let value_width = value.width(); // 실제 텍스트 폭 (색상 코드 제외)

            // 라벨 뒤 공백: 고정된 라벨 열 너비에서 라벨 길이를 뺀 나머지
            let spaces_after_label = label_column_width.saturating_sub(label_width);

            // 값 뒤 공백: 전체 너비에서 사용된 공간을 뺀 나머지
            let used_width = 1 + label_width + spaces_after_label + value_width + 1; // 양쪽 │와 공백
            let spaces_after_value = table_width.saturating_sub(used_width);

            let row = format!("│ {}{}{}{}│",
                label,
                " ".repeat(spaces_after_label),
                colored_value,
                " ".repeat(spaces_after_value));
            output.push_str(&format!("{}\n", row));

            // 요약 정보 전에 구분선 추가
            if i == 3 { // Duration 다음
                let separator = "├".to_string() + &"─".repeat(table_width) + "┤";
                output.push_str(&format!("{}\n", separator.blue()));
            }
        }

        // 하단 경계선
        let bottom_border = "└".to_string() + &"─".repeat(table_width) + "┘";
        output.push_str(&(bottom_border.blue().to_string() + "\n"));

        // 위협 목록
        if !result.threats.is_empty() {
            output.push('\n');
            output.push_str(&Self::format_threats_table(&result.threats)?);
        }

        Ok(output)
    }

    fn format_threats_table(threats: &[Threat]) -> Result<String> {
        if threats.is_empty() {
            return Ok("No threats found.".green().to_string());
        }

        // 데이터 준비
        let data: Vec<(String, String, String, String, String)> = threats
            .iter()
            .map(|threat| {
                let file = threat
                    .file_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();

                let threat_name = threat.name.clone();
                let threat_type = format!("{:?}", threat.threat_type);
                let severity = format!("{:?}", threat.severity);
                let action = format!("{:?}", threat.action_taken);

                (file, threat_name, threat_type, severity, action)
            })
            .collect();

        // 헤더
        let headers = ["File", "Threat", "Type", "Severity", "Action"];

        // Unicode-aware 길이 계산
        let mut max_widths = vec![
            headers[0].width(),
            headers[1].width(),
            headers[2].width(),
            headers[3].width(),
            headers[4].width(),
        ];

        for (file, threat, type_str, severity, action) in &data {
            max_widths[0] = max_widths[0].max(file.width());
            max_widths[1] = max_widths[1].max(threat.width());
            max_widths[2] = max_widths[2].max(type_str.width());
            max_widths[3] = max_widths[3].max(severity.width());
            max_widths[4] = max_widths[4].max(action.width());
        }

        // 터미널 너비에 맞게 조정 (80자 기준)
        let total_width: usize = max_widths.iter().sum::<usize>() + 16; // 구분자와 패딩 공간
        let mut column_widths = max_widths.clone();

        if total_width > 80 {
            // 열 우선순위에 따라 조정
            column_widths[0] = column_widths[0].min(12); // File
            column_widths[1] = column_widths[1].min(25); // Threat (가장 중요)
            column_widths[2] = column_widths[2].min(15); // Type
            column_widths[3] = column_widths[3].min(10); // Severity
            column_widths[4] = column_widths[4].min(10); // Action
        }

        let mut table_output = String::new();

        // 제목
        table_output.push_str(&format!("{}\n", "🦠 Detected Threats:".red().bold()));

        // 상단 경계선
        let top_border = Self::create_border_line(&column_widths, '┌', '┬', '┐');
        table_output.push_str(&format!("{}\n", top_border));

        // 헤더 행
        let header_row = Self::create_table_row(&headers.iter().map(|s| s.to_string()).collect::<Vec<_>>(), &column_widths);
        table_output.push_str(&format!("{}\n", header_row.bold()));

        // 헤더 구분선
        let header_separator = Self::create_border_line(&column_widths, '├', '┼', '┤');
        table_output.push_str(&format!("{}\n", header_separator));

        // 데이터 행들
        for (i, (file, threat, type_str, severity, action)) in data.iter().enumerate() {
            let row_data = vec![
                Self::truncate_to_width(file, column_widths[0]),
                Self::truncate_to_width(threat, column_widths[1]),
                Self::truncate_to_width(type_str, column_widths[2]),
                Self::truncate_to_width(severity, column_widths[3]),
                Self::truncate_to_width(action, column_widths[4]),
            ];

            let row = Self::create_table_row(&row_data, &column_widths);
            table_output.push_str(&format!("{}\n", row));

            // 마지막 행이 아니면 구분선 추가
            if i < data.len() - 1 {
                let row_separator = Self::create_border_line(&column_widths, '├', '┼', '┤');
                table_output.push_str(&format!("{}\n", row_separator));
            }
        }

        // 하단 경계선
        let bottom_border = Self::create_border_line(&column_widths, '└', '┴', '┘');
        table_output.push_str(&bottom_border);

        Ok(table_output)
    }

    // Unicode-aware 텍스트 자르기
    fn truncate_to_width(text: &str, max_width: usize) -> String {
        if text.width() <= max_width {
            text.to_string()
        } else if max_width <= 3 {
            "...".chars().take(max_width).collect()
        } else {
            let mut result = String::new();
            let mut current_width = 0;

            for ch in text.chars() {
                let char_width = ch.width().unwrap_or(0);
                if current_width + char_width + 3 > max_width {
                    result.push_str("...");
                    break;
                }
                result.push(ch);
                current_width += char_width;
            }
            result
        }
    }

    // 테이블 행 생성
    fn create_table_row(cells: &[String], widths: &[usize]) -> String {
        let mut row = String::from("│");

        for (i, cell) in cells.iter().enumerate() {
            let cell_width = cell.width();
            let padding = if cell_width < widths[i] {
                " ".repeat(widths[i] - cell_width)
            } else {
                String::new()
            };

            row.push(' ');
            row.push_str(cell);
            row.push_str(&padding);
            row.push_str(" │");
        }

        row
    }

    // 테이블 경계선 생성
    fn create_border_line(widths: &[usize], left: char, middle: char, right: char) -> String {
        let mut border = String::new();
        border.push(left);

        for (i, &width) in widths.iter().enumerate() {
            border.push_str(&"─".repeat(width + 2)); // +2 for padding spaces
            if i < widths.len() - 1 {
                border.push(middle);
            }
        }

        border.push(right);
        border
    }

    fn format_scan_result_json(result: &ScanResult) -> Result<String> {
        serde_json::to_string_pretty(result).map_err(|e| e.into())
    }

    fn format_threats_json(threats: &[Threat]) -> Result<String> {
        serde_json::to_string_pretty(threats).map_err(|e| e.into())
    }

    fn format_scan_result_csv(result: &ScanResult) -> Result<String> {
        let mut csv_output = String::new();

        // CSV 헤더
        csv_output.push_str("Scan ID,Type,Start Time,End Time,Duration (ms),Files Scanned,Threats Found,Status\n");

        // 스캔 정보
        let duration_ms = result.duration.unwrap_or_default().as_millis();
        csv_output.push_str(&format!(
            "\"{}\",\"{:?}\",\"{}\",\"{}\",{},{},{},\"{}\"\n",
            result.id,
            result.scan_type,
            result.start_time.format("%Y-%m-%d %H:%M:%S"),
            result.end_time.unwrap_or_else(chrono::Utc::now).format("%Y-%m-%d %H:%M:%S"),
            duration_ms,
            result.summary.files_scanned,
            result.summary.threats_found,
            result.status
        ));

        // 위협 정보가 있으면 추가
        if !result.threats.is_empty() {
            csv_output.push_str("\n\nThreat ID,Name,Type,Severity,File Path,File Size,Detection Method,Description\n");
            for threat in &result.threats {
                csv_output.push_str(&format!(
                    "\"{}\",\"{}\",\"{:?}\",\"{:?}\",\"{}\",{},\"{:?}\",\"{}\"\n",
                    threat.id,
                    threat.name,
                    threat.threat_type,
                    threat.severity,
                    threat.file_path.display(),
                    threat.file_size,
                    threat.detection_method,
                    threat.description.as_deref().unwrap_or("No description")
                ));
            }
        }

        Ok(csv_output)
    }

    fn format_threats_csv(threats: &[Threat]) -> Result<String> {
        let mut csv_output = String::new();

        // CSV 헤더
        csv_output.push_str("Threat ID,Name,Type,Severity,File Path,File Hash,File Size,Detected At,Detection Method,Description,Action Taken\n");

        // 위협 데이터
        for threat in threats {
            let action_taken = format!("{:?}", threat.action_taken);
            csv_output.push_str(&format!(
                "\"{}\",\"{}\",\"{:?}\",\"{:?}\",\"{}\",\"{}\",{},\"{}\",\"{:?}\",\"{}\",\"{}\"\n",
                threat.id,
                threat.name,
                threat.threat_type,
                threat.severity,
                threat.file_path.display(),
                threat.file_hash,
                threat.file_size,
                threat.detected_at.format("%Y-%m-%d %H:%M:%S"),
                threat.detection_method,
                threat.description.as_deref().unwrap_or("No description"),
                action_taken
            ));
        }

        Ok(csv_output)
    }

    fn format_scan_result_html(result: &ScanResult) -> Result<String> {
        let mut html_output = String::new();

        html_output.push_str("<!DOCTYPE html>\n<html lang=\"ko\">\n<head>\n");
        html_output.push_str("    <meta charset=\"UTF-8\">\n");
        html_output.push_str("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html_output.push_str("    <title>Seek Antivirus - Scan Report</title>\n");
        html_output.push_str("    <style>\n");
        html_output.push_str("        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }\n");
        html_output.push_str("        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
        html_output.push_str("        .header { border-bottom: 2px solid #007acc; padding-bottom: 10px; margin-bottom: 20px; }\n");
        html_output.push_str("        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }\n");
        html_output.push_str("        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; }\n");
        html_output.push_str("        .stat-value { font-size: 24px; font-weight: bold; color: #007acc; }\n");
        html_output.push_str("        .threat-high { color: #dc3545; }\n");
        html_output.push_str("        .threat-medium { color: #fd7e14; }\n");
        html_output.push_str("        .threat-low { color: #ffc107; }\n");
        html_output.push_str("        .threats-table { width: 100%; border-collapse: collapse; margin-top: 20px; }\n");
        html_output.push_str("        .threats-table th, .threats-table td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }\n");
        html_output.push_str("        .threats-table th { background-color: #007acc; color: white; }\n");
        html_output.push_str("        .threats-table tr:hover { background-color: #f5f5f5; }\n");
        html_output.push_str("    </style>\n</head>\n<body>\n");

        // 내용
        html_output.push_str("    <div class=\"container\">\n");
        html_output.push_str("        <div class=\"header\">\n");
        html_output.push_str("            <h1>🔍 Seek Antivirus - Scan Report</h1>\n");
        html_output.push_str(&format!("            <p><strong>Scan ID:</strong> {}</p>\n", result.id));
        html_output.push_str(&format!("            <p><strong>Generated:</strong> {}</p>\n", result.end_time.unwrap_or_else(chrono::Utc::now).format("%Y-%m-%d %H:%M:%S")));
        html_output.push_str("        </div>\n");

        // 요약 정보
        html_output.push_str("        <div class=\"summary\">\n");
        html_output.push_str(&format!("            <div class=\"stat-card\">\n                <div class=\"stat-value\">{}</div>\n                <div>Files Scanned</div>\n            </div>\n", result.summary.files_scanned));
        html_output.push_str(&format!("            <div class=\"stat-card\">\n                <div class=\"stat-value threat-high\">{}</div>\n                <div>Threats Found</div>\n            </div>\n", result.summary.threats_found));
        html_output.push_str(&format!("            <div class=\"stat-card\">\n                <div class=\"stat-value\">{} ms</div>\n                <div>Duration</div>\n            </div>\n", result.duration.unwrap_or_default().as_millis()));
        html_output.push_str(&format!("            <div class=\"stat-card\">\n                <div class=\"stat-value\">{}</div>\n                <div>Status</div>\n            </div>\n", result.status));
        html_output.push_str("        </div>\n");

        // 위협 테이블
        if !result.threats.is_empty() {
            html_output.push_str("        <h2>🚨 Detected Threats</h2>\n");
            html_output.push_str("        <table class=\"threats-table\">\n");
            html_output.push_str("            <thead>\n                <tr>\n                    <th>Name</th>\n                    <th>File Path</th>\n                    <th>Severity</th>\n                    <th>Type</th>\n                    <th>Size</th>\n                    <th>Action</th>\n                </tr>\n            </thead>\n");
            html_output.push_str("            <tbody>\n");

            for threat in &result.threats {
                let severity_class = match threat.severity {
                    crate::data::models::threat::ThreatSeverity::Critical | crate::data::models::threat::ThreatSeverity::High => "threat-high",
                    crate::data::models::threat::ThreatSeverity::Medium => "threat-medium",
                    crate::data::models::threat::ThreatSeverity::Low => "threat-low",
                };

                let action_taken = format!("{:?}", threat.action_taken);
                html_output.push_str(&format!(
                    "                <tr>\n                    <td><strong>{}</strong></td>\n                    <td>{}</td>\n                    <td class=\"{}\"><strong>{:?}</strong></td>\n                    <td>{:?}</td>\n                    <td>{} bytes</td>\n                    <td>{}</td>\n                </tr>\n",
                    threat.name,
                    threat.file_path.display(),
                    severity_class,
                    threat.severity,
                    threat.threat_type,
                    threat.file_size,
                    action_taken
                ));
            }

            html_output.push_str("            </tbody>\n        </table>\n");
        } else {
            html_output.push_str("        <div style=\"text-align: center; padding: 40px; color: #28a745;\">\n");
            html_output.push_str("            <h2>✅ No threats detected</h2>\n");
            html_output.push_str("            <p>Your system is clean!</p>\n");
            html_output.push_str("        </div>\n");
        }

        html_output.push_str("    </div>\n</body>\n</html>");

        Ok(html_output)
    }

    fn format_threats_html(threats: &[Threat]) -> Result<String> {
        let mut html_output = String::new();

        html_output.push_str("<!DOCTYPE html>\n<html lang=\"ko\">\n<head>\n");
        html_output.push_str("    <meta charset=\"UTF-8\">\n");
        html_output.push_str("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html_output.push_str("    <title>Seek Antivirus - Threat Report</title>\n");
        html_output.push_str("    <style>\n");
        html_output.push_str("        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }\n");
        html_output.push_str("        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
        html_output.push_str("        .threat-card { border: 1px solid #ddd; border-radius: 6px; margin-bottom: 15px; padding: 15px; }\n");
        html_output.push_str("        .threat-high { border-left: 5px solid #dc3545; background-color: #f8d7da; }\n");
        html_output.push_str("        .threat-medium { border-left: 5px solid #fd7e14; background-color: #fff3cd; }\n");
        html_output.push_str("        .threat-low { border-left: 5px solid #ffc107; background-color: #fff3cd; }\n");
        html_output.push_str("        .threat-critical { border-left: 5px solid #721c24; background-color: #f5c6cb; }\n");
        html_output.push_str("        .threat-name { font-size: 18px; font-weight: bold; margin-bottom: 5px; }\n");
        html_output.push_str("        .threat-path { font-family: monospace; color: #666; word-break: break-all; }\n");
        html_output.push_str("        .threat-details { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-top: 10px; }\n");
        html_output.push_str("        .detail-item { background: #f8f9fa; padding: 8px; border-radius: 4px; }\n");
        html_output.push_str("        .detail-label { font-weight: bold; font-size: 12px; color: #666; }\n");
        html_output.push_str("        .detail-value { font-size: 14px; }\n");
        html_output.push_str("    </style>\n</head>\n<body>\n");

        html_output.push_str("    <div class=\"container\">\n");
        html_output.push_str("        <h1>🚨 Detected Threats Report</h1>\n");
        html_output.push_str(&format!("        <p><strong>Total Threats:</strong> {}</p>\n", threats.len()));
        html_output.push_str(&format!("        <p><strong>Generated:</strong> {}</p>\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));

        if threats.is_empty() {
            html_output.push_str("        <div style=\"text-align: center; padding: 40px; color: #28a745;\">\n");
            html_output.push_str("            <h2>✅ No threats detected</h2>\n");
            html_output.push_str("            <p>Your system is clean!</p>\n");
            html_output.push_str("        </div>\n");
        } else {
            for threat in threats {
                let severity_class = match threat.severity {
                    crate::data::models::threat::ThreatSeverity::Critical => "threat-critical",
                    crate::data::models::threat::ThreatSeverity::High => "threat-high",
                    crate::data::models::threat::ThreatSeverity::Medium => "threat-medium",
                    crate::data::models::threat::ThreatSeverity::Low => "threat-low",
                };

                html_output.push_str(&format!("        <div class=\"threat-card {}\">\n", severity_class));
                html_output.push_str(&format!("            <div class=\"threat-name\">{}</div>\n", threat.name));
                html_output.push_str(&format!("            <div class=\"threat-path\">{}</div>\n", threat.file_path.display()));

                html_output.push_str("            <div class=\"threat-details\">\n");
                html_output.push_str(&format!("                <div class=\"detail-item\">\n                    <div class=\"detail-label\">Severity</div>\n                    <div class=\"detail-value\">{:?}</div>\n                </div>\n", threat.severity));
                html_output.push_str(&format!("                <div class=\"detail-item\">\n                    <div class=\"detail-label\">Type</div>\n                    <div class=\"detail-value\">{:?}</div>\n                </div>\n", threat.threat_type));
                html_output.push_str(&format!("                <div class=\"detail-item\">\n                    <div class=\"detail-label\">Detection Method</div>\n                    <div class=\"detail-value\">{:?}</div>\n                </div>\n", threat.detection_method));
                html_output.push_str(&format!("                <div class=\"detail-item\">\n                    <div class=\"detail-label\">File Size</div>\n                    <div class=\"detail-value\">{} bytes</div>\n                </div>\n", threat.file_size));
                let action_taken = format!("{:?}", threat.action_taken);
                html_output.push_str(&format!("                <div class=\"detail-item\">\n                    <div class=\"detail-label\">Action Taken</div>\n                    <div class=\"detail-value\">{}</div>\n                </div>\n", action_taken));
                html_output.push_str(&format!("                <div class=\"detail-item\">\n                    <div class=\"detail-label\">Detected At</div>\n                    <div class=\"detail-value\">{}</div>\n                </div>\n", threat.detected_at.format("%Y-%m-%d %H:%M:%S")));
                html_output.push_str("            </div>\n");

                if let Some(ref desc) = threat.description {
                    if !desc.is_empty() {
                        html_output.push_str(&format!("            <div style=\"margin-top: 10px; font-style: italic;\">\n                <strong>Description:</strong> {}\n            </div>\n", desc));
                    }
                }

                html_output.push_str("        </div>\n");
            }
        }

        html_output.push_str("    </div>\n</body>\n</html>");

        Ok(html_output)
    }

    pub fn print_progress(current: u64, total: u64, file_name: &str) {
        let percentage = if total > 0 { (current * 100) / total } else { 0 };
        let bar_length = 50;
        let filled_length = (percentage * bar_length) / 100;

        let bar = "█".repeat(filled_length as usize) + &"░".repeat((bar_length - filled_length) as usize);

        print!(
            "\r🔍 Scanning: {} [{bar}] {}% ({}/{} files) - {}",
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