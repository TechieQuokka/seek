use crate::cli::args::{ReportArgs, ReportType, Period};
use crate::data::models::{
    config::AppConfig,
    scan_result::ScanResult,
    threat::Threat,
};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub id: String,
    pub timestamp: u64,
    pub scan_type: String,
    pub target_path: PathBuf,
    pub duration_seconds: u64,
    pub files_scanned: usize,
    pub threats_found: usize,
    pub threats: Vec<Threat>,
    pub status: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatStatistics {
    pub total_threats: usize,
    pub by_severity: HashMap<String, usize>,
    pub by_type: HashMap<String, usize>,
    pub by_detection_method: HashMap<String, usize>,
    pub unique_threat_names: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemReport {
    pub report_id: String,
    pub generated_at: u64,
    pub report_period: String,
    pub total_scans: usize,
    pub successful_scans: usize,
    pub failed_scans: usize,
    pub total_files_scanned: usize,
    pub threat_statistics: ThreatStatistics,
    pub performance_metrics: PerformanceMetrics,
    pub security_summary: SecuritySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub average_scan_time: f64,
    pub fastest_scan_time: u64,
    pub slowest_scan_time: u64,
    pub average_files_per_second: f64,
    pub peak_memory_usage: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub critical_threats: usize,
    pub high_threats: usize,
    pub medium_threats: usize,
    pub low_threats: usize,
    pub clean_scans: usize,
    pub quarantined_files: usize,
    pub most_common_threat_type: Option<String>,
    pub threat_trend: String, // "increasing", "decreasing", "stable"
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportDatabase {
    pub scan_reports: Vec<ScanReport>,
    pub system_reports: Vec<SystemReport>,
    pub metadata: ReportMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub total_reports: usize,
    pub oldest_report: Option<u64>,
    pub newest_report: Option<u64>,
    pub last_cleanup: u64,
}

pub struct ReportService {
    #[allow(dead_code)]
    config: AppConfig,
    database_path: PathBuf,
}

impl ReportService {
    pub fn new(config: AppConfig) -> Result<Self> {
        let database_path = config.signature.database_path.join("reports.db");

        // 리포트 디렉토리 생성
        if let Some(parent) = database_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
                info!("Created reports directory: {}", parent.display());
            }
        }

        Ok(Self {
            config,
            database_path,
        })
    }

    pub async fn record_scan_result(&self, scan_result: &ScanResult) -> Result<String> {
        let report_id = uuid::Uuid::new_v4().to_string();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let scan_report = ScanReport {
            id: report_id.clone(),
            timestamp: current_time,
            scan_type: format!("{:?}", scan_result.scan_type),
            target_path: scan_result.target_path.clone(),
            duration_seconds: scan_result.duration
                .map(|d| d.as_secs())
                .unwrap_or(0),
            files_scanned: scan_result.summary.files_scanned as usize,
            threats_found: scan_result.summary.threats_found as usize,
            threats: scan_result.threats.clone(),
            status: format!("{:?}", scan_result.status),
            error_message: None,
        };

        self.add_scan_report(scan_report).await?;
        debug!("Scan result recorded with ID: {}", report_id);
        Ok(report_id)
    }

    pub async fn generate_report(&self, args: ReportArgs) -> Result<String> {
        let report_type = args.report_type.unwrap_or(ReportType::System);
        let period = args.period.unwrap_or(Period::Week);

        match report_type {
            ReportType::Scan => self.generate_scan_report(period, args.filter).await,
            ReportType::Threat => self.generate_threat_report(period, args.filter).await,
            ReportType::System => self.generate_system_report(period).await,
        }
    }

    pub async fn get_scan_history(&self, days: u32, filter: Option<&str>) -> Result<Vec<ScanReport>> {
        let database = self.load_database().await?;
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - (days as u64 * 24 * 60 * 60);

        let mut reports: Vec<ScanReport> = database.scan_reports
            .into_iter()
            .filter(|r| r.timestamp >= cutoff_time)
            .collect();

        if let Some(filter_text) = filter {
            reports.retain(|r| {
                r.target_path.to_string_lossy().contains(filter_text) ||
                r.scan_type.contains(filter_text) ||
                r.threats.iter().any(|t| t.name.contains(filter_text) || t.threat_type.to_string().contains(filter_text))
            });
        }

        reports.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(reports)
    }

    pub async fn get_threat_statistics(&self, days: u32) -> Result<ThreatStatistics> {
        let reports = self.get_scan_history(days, None).await?;
        let mut stats = ThreatStatistics {
            total_threats: 0,
            by_severity: HashMap::new(),
            by_type: HashMap::new(),
            by_detection_method: HashMap::new(),
            unique_threat_names: 0,
        };

        let mut unique_names = std::collections::HashSet::new();

        for report in reports {
            for threat in report.threats {
                stats.total_threats += 1;
                unique_names.insert(threat.name.clone());

                // 심각도별 통계
                let severity = format!("{:?}", threat.severity);
                *stats.by_severity.entry(severity).or_insert(0) += 1;

                // 타입별 통계
                *stats.by_type.entry(threat.threat_type.to_string()).or_insert(0) += 1;

                // 탐지 방법별 통계
                *stats.by_detection_method.entry(threat.detection_method.to_string()).or_insert(0) += 1;
            }
        }

        stats.unique_threat_names = unique_names.len();
        Ok(stats)
    }

    pub async fn cleanup_old_reports(&self, max_age_days: u32) -> Result<usize> {
        let mut database = self.load_database().await?;
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - (max_age_days as u64 * 24 * 60 * 60);

        let initial_count = database.scan_reports.len();
        database.scan_reports.retain(|r| r.timestamp >= cutoff_time);
        database.system_reports.retain(|r| r.generated_at >= cutoff_time);

        let removed_count = initial_count - database.scan_reports.len();

        if removed_count > 0 {
            database.metadata.total_reports = database.scan_reports.len();
            database.metadata.last_cleanup = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            self.save_database(&database).await?;
            info!("Cleaned up {} old reports", removed_count);
        }

        Ok(removed_count)
    }

    async fn generate_scan_report(&self, period: Period, filter: Option<String>) -> Result<String> {
        let days = self.period_to_days(period);
        let reports = self.get_scan_history(days, filter.as_deref()).await?;

        let mut report = String::new();
        report.push_str(&format!("📊 Scan Report (Last {} days)\n", days));
        report.push_str(&format!("{}\n\n", "=".repeat(50)));

        report.push_str(&format!("Total scans: {}\n", reports.len()));

        let successful = reports.iter().filter(|r| r.status == "Completed").count();
        let failed = reports.len() - successful;

        report.push_str(&format!("Successful scans: {}\n", successful));
        report.push_str(&format!("Failed scans: {}\n", failed));

        let total_files: usize = reports.iter().map(|r| r.files_scanned).sum();
        let total_threats: usize = reports.iter().map(|r| r.threats_found).sum();

        report.push_str(&format!("Total files scanned: {}\n", total_files));
        report.push_str(&format!("Total threats found: {}\n\n", total_threats));

        if !reports.is_empty() {
            report.push_str("Recent Scans:\n");
            report.push_str(&format!("{:<20} {:<30} {:<10} {:<10} {:<10}\n",
                "Date", "Path", "Files", "Threats", "Duration"));
            report.push_str(&format!("{}\n", "-".repeat(85)));

            for (_i, scan_report) in reports.iter().take(10).enumerate() {
                let date = chrono::DateTime::from_timestamp(scan_report.timestamp as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "Unknown".to_string());

                let path_str = scan_report.target_path.display().to_string();
                let short_path = if path_str.len() > 28 {
                    format!("{}...", &path_str[..25])
                } else {
                    path_str
                };

                report.push_str(&format!("{:<20} {:<30} {:<10} {:<10} {:<10}s\n",
                    date,
                    short_path,
                    scan_report.files_scanned,
                    scan_report.threats_found,
                    scan_report.duration_seconds
                ));
            }
        }

        Ok(report)
    }

    async fn generate_threat_report(&self, period: Period, _filter: Option<String>) -> Result<String> {
        let days = self.period_to_days(period);
        let stats = self.get_threat_statistics(days).await?;

        let mut report = String::new();
        report.push_str(&format!("🦠 Threat Report (Last {} days)\n", days));
        report.push_str(&format!("{}\n\n", "=".repeat(50)));

        report.push_str(&format!("Total threats detected: {}\n", stats.total_threats));
        report.push_str(&format!("Unique threat types: {}\n\n", stats.unique_threat_names));

        // 심각도별 통계
        report.push_str("Threats by Severity:\n");
        for (severity, count) in &stats.by_severity {
            let percentage = if stats.total_threats > 0 {
                (*count as f64 / stats.total_threats as f64) * 100.0
            } else {
                0.0
            };
            report.push_str(&format!("  {}: {} ({:.1}%)\n", severity, count, percentage));
        }

        // 타입별 통계
        report.push_str("\nThreats by Type:\n");
        let mut type_vec: Vec<_> = stats.by_type.iter().collect();
        type_vec.sort_by(|a, b| b.1.cmp(a.1));

        for (threat_type, count) in type_vec.iter().take(10) {
            let percentage = if stats.total_threats > 0 {
                (**count as f64 / stats.total_threats as f64) * 100.0
            } else {
                0.0
            };
            report.push_str(&format!("  {}: {} ({:.1}%)\n", threat_type, count, percentage));
        }

        // 탐지 방법별 통계
        report.push_str("\nDetection Methods:\n");
        for (method, count) in &stats.by_detection_method {
            let percentage = if stats.total_threats > 0 {
                (*count as f64 / stats.total_threats as f64) * 100.0
            } else {
                0.0
            };
            report.push_str(&format!("  {}: {} ({:.1}%)\n", method, count, percentage));
        }

        Ok(report)
    }

    async fn generate_system_report(&self, period: Period) -> Result<String> {
        let days = self.period_to_days(period);
        let reports = self.get_scan_history(days, None).await?;

        let mut report = String::new();
        report.push_str(&format!("🖥️  System Report (Last {} days)\n", days));
        report.push_str(&format!("{}\n\n", "=".repeat(50)));

        // 기본 통계
        let total_scans = reports.len();
        let successful_scans = reports.iter().filter(|r| r.status == "Completed").count();
        let failed_scans = total_scans - successful_scans;

        report.push_str(&format!("Scan Statistics:\n"));
        report.push_str(&format!("  Total scans: {}\n", total_scans));
        report.push_str(&format!("  Successful: {} ({:.1}%)\n",
            successful_scans,
            if total_scans > 0 { (successful_scans as f64 / total_scans as f64) * 100.0 } else { 0.0 }
        ));
        report.push_str(&format!("  Failed: {} ({:.1}%)\n\n",
            failed_scans,
            if total_scans > 0 { (failed_scans as f64 / total_scans as f64) * 100.0 } else { 0.0 }
        ));

        // 성능 메트릭
        if !reports.is_empty() {
            let durations: Vec<u64> = reports.iter().map(|r| r.duration_seconds).collect();
            let total_files: usize = reports.iter().map(|r| r.files_scanned).sum();
            let total_time: u64 = durations.iter().sum();

            let avg_duration = total_time as f64 / reports.len() as f64;
            let min_duration = *durations.iter().min().unwrap_or(&0);
            let max_duration = *durations.iter().max().unwrap_or(&0);
            let avg_files_per_sec = if total_time > 0 {
                total_files as f64 / total_time as f64
            } else {
                0.0
            };

            report.push_str(&format!("Performance Metrics:\n"));
            report.push_str(&format!("  Average scan time: {:.1}s\n", avg_duration));
            report.push_str(&format!("  Fastest scan: {}s\n", min_duration));
            report.push_str(&format!("  Slowest scan: {}s\n", max_duration));
            report.push_str(&format!("  Average throughput: {:.1} files/sec\n", avg_files_per_sec));
            report.push_str(&format!("  Total files processed: {}\n\n", total_files));
        }

        // 보안 요약
        let stats = self.get_threat_statistics(days).await?;
        report.push_str(&format!("Security Summary:\n"));
        report.push_str(&format!("  Total threats detected: {}\n", stats.total_threats));
        report.push_str(&format!("  Unique threat types: {}\n", stats.unique_threat_names));

        let clean_scans = reports.iter().filter(|r| r.threats_found == 0).count();
        report.push_str(&format!("  Clean scans: {} ({:.1}%)\n",
            clean_scans,
            if total_scans > 0 { (clean_scans as f64 / total_scans as f64) * 100.0 } else { 0.0 }
        ));

        if let Some((most_common_type, count)) = stats.by_type.iter().max_by_key(|(_, &v)| v) {
            report.push_str(&format!("  Most common threat: {} ({} instances)\n", most_common_type, count));
        }

        Ok(report)
    }

    async fn add_scan_report(&self, scan_report: ScanReport) -> Result<()> {
        let mut database = self.load_database().await?;

        database.scan_reports.push(scan_report);
        database.metadata.total_reports = database.scan_reports.len();
        database.metadata.newest_report = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        if database.metadata.oldest_report.is_none() {
            database.metadata.oldest_report = database.metadata.newest_report;
        }

        self.save_database(&database).await?;
        Ok(())
    }

    async fn load_database(&self) -> Result<ReportDatabase> {
        if !self.database_path.exists() {
            return Ok(ReportDatabase {
                scan_reports: Vec::new(),
                system_reports: Vec::new(),
                metadata: ReportMetadata {
                    total_reports: 0,
                    oldest_report: None,
                    newest_report: None,
                    last_cleanup: 0,
                },
            });
        }

        let content = fs::read_to_string(&self.database_path)?;
        let database: ReportDatabase = serde_json::from_str(&content)?;
        Ok(database)
    }

    async fn save_database(&self, database: &ReportDatabase) -> Result<()> {
        let content = serde_json::to_string_pretty(database)?;
        fs::write(&self.database_path, content)?;
        Ok(())
    }

    fn period_to_days(&self, period: Period) -> u32 {
        match period {
            Period::Day => 1,
            Period::Week => 7,
            Period::Month => 30,
            Period::Year => 365,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::data::models::scan_result::{ScanType, ScanStatus, ScanSummary};

    #[tokio::test]
    async fn test_report_service_creation() {
        let temp_dir = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.data.database_dir = temp_dir.path().to_path_buf();

        let service = ReportService::new(config).unwrap();
        assert!(service.database_path.exists() || !service.database_path.exists());
    }

    #[tokio::test]
    async fn test_scan_report_recording() {
        let temp_dir = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.data.database_dir = temp_dir.path().to_path_buf();

        let service = ReportService::new(config).unwrap();

        let mut scan_result = ScanResult::new(ScanType::Quick, temp_dir.path().to_path_buf());
        scan_result.status = ScanStatus::Completed;
        scan_result.summary = ScanSummary {
            files_scanned: 10,
            threats_found: 1,
            duration_seconds: 5,
            total_size_scanned: 1024,
        };

        let report_id = service.record_scan_result(&scan_result).await.unwrap();
        assert!(!report_id.is_empty());

        let history = service.get_scan_history(1, None).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].files_scanned, 10);
        assert_eq!(history[0].threats_found, 1);
    }

    #[tokio::test]
    async fn test_threat_statistics() {
        let temp_dir = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.data.database_dir = temp_dir.path().to_path_buf();

        let service = ReportService::new(config).unwrap();

        // 가짜 위협이 포함된 스캔 결과 생성
        let mut scan_result = ScanResult::new(ScanType::Quick, temp_dir.path().to_path_buf());
        scan_result.threats.push(Threat {
            name: "Test Malware".to_string(),
            threat_type: "trojan".to_string(),
            severity: ThreatSeverity::High,
            description: None,
            file_path: temp_dir.path().join("malware.exe"),
            detection_method: "signature".to_string(),
            risk_score: 85,
            metadata: HashMap::new(),
        });

        service.record_scan_result(&scan_result).await.unwrap();

        let stats = service.get_threat_statistics(1).await.unwrap();
        assert_eq!(stats.total_threats, 1);
        assert_eq!(stats.unique_threat_names, 1);
        assert_eq!(stats.by_type.get("trojan"), Some(&1));
    }
}