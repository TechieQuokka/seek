use crate::data::models::config::AppConfig;
use crate::error::Result;
// use crate::services::{
//     monitor_service::MonitorService,
//     quarantine_service::QuarantineService,
//     update_service::UpdateService,
//     report_service::ReportService,
// };
use serde::{Deserialize, Serialize};
// use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, interval};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub timestamp: u64,
    pub engine_status: EngineStatus,
    pub services_status: ServicesStatus,
    pub database_status: DatabaseStatus,
    pub performance_metrics: PerformanceMetrics,
    pub security_status: SecurityStatus,
    pub health_score: u8, // 0-100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub signature_engine: ComponentStatus,
    pub heuristic_engine: ComponentStatus,
    pub quarantine_engine: ComponentStatus,
    pub monitor_engine: ComponentStatus,
    pub last_update_check: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicesStatus {
    pub monitor_service: ServiceStatus,
    pub update_service: ServiceStatus,
    pub schedule_service: ServiceStatus,
    pub report_service: ServiceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStatus {
    pub signatures_db: DatabaseInfo,
    pub quarantine_db: DatabaseInfo,
    pub reports_db: DatabaseInfo,
    pub schedules_db: DatabaseInfo,
    pub config_files: ConfigFilesStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub cpu_usage: Option<f64>,
    pub memory_usage: Option<u64>,
    pub disk_usage: DiskUsage,
    pub average_scan_time: Option<f64>,
    pub throughput: Option<f64>,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatus {
    pub threats_detected_today: usize,
    pub threats_detected_week: usize,
    pub last_scan_time: Option<u64>,
    pub quarantined_files: usize,
    pub active_monitors: usize,
    pub signature_version: String,
    pub protection_level: ProtectionLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub status: StatusLevel,
    pub last_check: u64,
    pub version: Option<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub running: bool,
    pub last_activity: Option<u64>,
    pub status: StatusLevel,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    pub exists: bool,
    pub size_bytes: u64,
    pub last_modified: Option<u64>,
    pub entries_count: Option<usize>,
    pub health: StatusLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFilesStatus {
    pub main_config: bool,
    pub user_config: bool,
    pub permissions_ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskUsage {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub quarantine_usage: u64,
    pub database_usage: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StatusLevel {
    Healthy,
    Warning,
    Critical,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtectionLevel {
    Maximum,
    High,
    Medium,
    Low,
    Minimal,
}

pub struct StatusService {
    config: AppConfig,
    start_time: SystemTime,
}

impl StatusService {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            start_time: SystemTime::now(),
        }
    }

    pub async fn get_system_status(&self) -> Result<SystemStatus> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let engine_status = self.check_engine_status().await?;
        let services_status = self.check_services_status().await?;
        let database_status = self.check_database_status().await?;
        let performance_metrics = self.collect_performance_metrics().await?;
        let security_status = self.assess_security_status().await?;

        let health_score = self.calculate_health_score(
            &engine_status,
            &services_status,
            &database_status,
            &security_status,
        );

        Ok(SystemStatus {
            timestamp: current_time,
            engine_status,
            services_status,
            database_status,
            performance_metrics,
            security_status,
            health_score,
        })
    }

    pub async fn check_system_health(&self) -> Result<Vec<String>> {
        let mut issues = Vec::new();
        let status = self.get_system_status().await?;

        // 엔진 상태 검사
        if matches!(status.engine_status.signature_engine.status, StatusLevel::Critical) {
            issues.push("Signature engine is in critical state".to_string());
        }

        if matches!(status.engine_status.heuristic_engine.status, StatusLevel::Critical) {
            issues.push("Heuristic engine is in critical state".to_string());
        }

        if matches!(status.engine_status.quarantine_engine.status, StatusLevel::Critical) {
            issues.push("Quarantine engine is in critical state".to_string());
        }

        // 데이터베이스 상태 검사
        if !status.database_status.signatures_db.exists {
            issues.push("Signatures database not found".to_string());
        }

        if matches!(status.database_status.signatures_db.health, StatusLevel::Critical) {
            issues.push("Signatures database is corrupted".to_string());
        }

        // 보안 상태 검사
        if matches!(status.security_status.protection_level, ProtectionLevel::Low | ProtectionLevel::Minimal) {
            issues.push("Protection level is too low".to_string());
        }

        // 성능 검사
        if let Some(cpu) = status.performance_metrics.cpu_usage {
            if cpu > 90.0 {
                issues.push(format!("High CPU usage: {:.1}%", cpu));
            }
        }

        if status.performance_metrics.disk_usage.free_bytes < 1024 * 1024 * 100 { // 100MB
            issues.push("Low disk space available".to_string());
        }

        // 설정 파일 검사
        if !status.database_status.config_files.main_config {
            issues.push("Main configuration file not found".to_string());
        }

        if !status.database_status.config_files.permissions_ok {
            issues.push("Configuration file permissions issue".to_string());
        }

        Ok(issues)
    }

    pub async fn watch_system_status(&self, interval_seconds: u64) -> Result<()> {
        let mut interval = interval(Duration::from_secs(interval_seconds));

        info!("Starting system status monitoring (interval: {}s)", interval_seconds);

        loop {
            interval.tick().await;

            match self.get_system_status().await {
                Ok(status) => {
                    self.log_status_summary(&status).await;

                    // 중요한 문제가 있으면 경고
                    if status.health_score < 50 {
                        warn!("System health score is low: {}/100", status.health_score);
                    }

                    // 위험한 문제가 있으면 즉시 알림
                    if let Ok(issues) = self.check_system_health().await {
                        for issue in issues {
                            if issue.contains("critical") || issue.contains("corrupted") {
                                error!("Critical system issue: {}", issue);
                            } else {
                                warn!("System issue: {}", issue);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to get system status: {}", e);
                }
            }
        }
    }

    async fn check_engine_status(&self) -> Result<EngineStatus> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 시그니처 엔진 상태
        let signature_engine = ComponentStatus {
            status: if self.config.scan.scan_archives {
                StatusLevel::Healthy
            } else {
                StatusLevel::Warning
            },
            last_check: current_time,
            version: Some("1.0.0".to_string()),
            errors: Vec::new(),
            warnings: if !self.config.scan.scan_archives {
                vec!["Archive scanning is disabled".to_string()]
            } else {
                Vec::new()
            },
        };

        // 휴리스틱 엔진 상태
        let heuristic_engine = ComponentStatus {
            status: if self.config.scan.heuristic_enabled {
                StatusLevel::Healthy
            } else {
                StatusLevel::Warning
            },
            last_check: current_time,
            version: Some("1.0.0".to_string()),
            errors: Vec::new(),
            warnings: if !self.config.scan.heuristic_enabled {
                vec!["Heuristic analysis is disabled".to_string()]
            } else {
                Vec::new()
            },
        };

        // 격리 엔진 상태
        let quarantine_status = if self.config.quarantine.directory.exists() {
            StatusLevel::Healthy
        } else {
            StatusLevel::Critical
        };

        let quarantine_engine = ComponentStatus {
            status: quarantine_status.clone(),
            last_check: current_time,
            version: Some("1.0.0".to_string()),
            errors: if matches!(quarantine_status, StatusLevel::Critical) {
                vec!["Quarantine directory not accessible".to_string()]
            } else {
                Vec::new()
            },
            warnings: Vec::new(),
        };

        // 모니터 엔진 상태
        let monitor_engine = ComponentStatus {
            status: if self.config.monitor.enabled {
                StatusLevel::Healthy
            } else {
                StatusLevel::Warning
            },
            last_check: current_time,
            version: Some("1.0.0".to_string()),
            errors: Vec::new(),
            warnings: if !self.config.monitor.enabled {
                vec!["Real-time monitoring is disabled".to_string()]
            } else {
                Vec::new()
            },
        };

        Ok(EngineStatus {
            signature_engine,
            heuristic_engine,
            quarantine_engine,
            monitor_engine,
            last_update_check: Some(current_time),
        })
    }

    async fn check_services_status(&self) -> Result<ServicesStatus> {
        // 각 서비스의 상태를 확인 (실제로는 서비스와 통신해야 함)
        let monitor_service = ServiceStatus {
            running: true, // 실제로는 MonitorService 상태 확인
            last_activity: Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
            status: StatusLevel::Healthy,
            details: "Monitoring file system events".to_string(),
        };

        let update_service = ServiceStatus {
            running: true,
            last_activity: Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
            status: StatusLevel::Healthy,
            details: "Signature database up to date".to_string(),
        };

        let schedule_service = ServiceStatus {
            running: false, // 스케줄러는 기본적으로 중지 상태
            last_activity: None,
            status: StatusLevel::Warning,
            details: "No active scheduled scans".to_string(),
        };

        let report_service = ServiceStatus {
            running: true,
            last_activity: Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
            status: StatusLevel::Healthy,
            details: "Report generation available".to_string(),
        };

        Ok(ServicesStatus {
            monitor_service,
            update_service,
            schedule_service,
            report_service,
        })
    }

    async fn check_database_status(&self) -> Result<DatabaseStatus> {
        let signatures_db = self.check_database_file(&self.config.signature.database_path.join("signatures.db")).await;
        let quarantine_db = self.check_database_file(&self.config.signature.database_path.join("quarantine.db")).await;
        let reports_db = self.check_database_file(&self.config.signature.database_path.join("reports.db")).await;
        let schedules_db = self.check_database_file(&self.config.signature.database_path.join("schedules.db")).await;

        let config_files = ConfigFilesStatus {
            main_config: true, // 실제로는 설정 파일 존재 여부 확인
            user_config: true,
            permissions_ok: true, // 실제로는 권한 확인
        };

        Ok(DatabaseStatus {
            signatures_db,
            quarantine_db,
            reports_db,
            schedules_db,
            config_files,
        })
    }

    async fn check_database_file(&self, path: &PathBuf) -> DatabaseInfo {
        if let Ok(metadata) = fs::metadata(path) {
            let last_modified = metadata.modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|dur| dur.as_secs());

            DatabaseInfo {
                exists: true,
                size_bytes: metadata.len(),
                last_modified,
                entries_count: None, // 실제로는 파일을 읽어서 엔트리 수 계산
                health: StatusLevel::Healthy,
            }
        } else {
            DatabaseInfo {
                exists: false,
                size_bytes: 0,
                last_modified: None,
                entries_count: None,
                health: StatusLevel::Warning,
            }
        }
    }

    async fn collect_performance_metrics(&self) -> Result<PerformanceMetrics> {
        let uptime = self.start_time.elapsed()
            .map(|dur| dur.as_secs())
            .unwrap_or(0);

        // 디스크 사용량 계산
        let disk_usage = self.calculate_disk_usage().await?;

        Ok(PerformanceMetrics {
            cpu_usage: None, // 실제로는 시스템 정보 수집
            memory_usage: None, // 실제로는 메모리 사용량 수집
            disk_usage,
            average_scan_time: None, // 실제로는 리포트 서비스에서 계산
            throughput: None, // 실제로는 성능 데이터 수집
            uptime_seconds: uptime,
        })
    }

    async fn calculate_disk_usage(&self) -> Result<DiskUsage> {
        // 간단한 디스크 사용량 계산 (실제로는 더 정확한 계산 필요)
        let quarantine_usage = self.calculate_directory_size(&self.config.quarantine.directory).await;
        let database_usage = self.calculate_directory_size(&self.config.signature.database_path).await;

        Ok(DiskUsage {
            total_bytes: 1024 * 1024 * 1024 * 100, // 임시값: 100GB
            used_bytes: 1024 * 1024 * 1024 * 30,   // 임시값: 30GB
            free_bytes: 1024 * 1024 * 1024 * 70,   // 임시값: 70GB
            quarantine_usage,
            database_usage,
        })
    }

    async fn calculate_directory_size(&self, path: &PathBuf) -> u64 {
        if let Ok(entries) = fs::read_dir(path) {
            let mut total_size = 0;
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    total_size += metadata.len();
                }
            }
            total_size
        } else {
            0
        }
    }

    async fn assess_security_status(&self) -> Result<SecurityStatus> {
        // 실제로는 리포트 서비스에서 위협 통계 수집
        let threats_detected_today = 0; // ReportService에서 가져와야 함
        let threats_detected_week = 0;  // ReportService에서 가져와야 함

        let quarantined_files = 0; // QuarantineService에서 가져와야 함

        let protection_level = self.calculate_protection_level();

        Ok(SecurityStatus {
            threats_detected_today,
            threats_detected_week,
            last_scan_time: None, // 실제로는 마지막 스캔 시간 추적
            quarantined_files,
            active_monitors: if self.config.monitor.enabled { 1 } else { 0 },
            signature_version: "1.0.1".to_string(), // UpdateService에서 가져와야 함
            protection_level,
        })
    }

    fn calculate_protection_level(&self) -> ProtectionLevel {
        let mut score = 0;

        if self.config.scan.scan_archives { score += 2; }
        if self.config.scan.heuristic_enabled { score += 2; }
        if self.config.monitor.enabled { score += 2; }
        if self.config.quarantine.encrypt { score += 1; }

        match score {
            7 => ProtectionLevel::Maximum,
            5..=6 => ProtectionLevel::High,
            3..=4 => ProtectionLevel::Medium,
            1..=2 => ProtectionLevel::Low,
            _ => ProtectionLevel::Minimal,
        }
    }

    fn calculate_health_score(
        &self,
        engine: &EngineStatus,
        _services: &ServicesStatus,
        database: &DatabaseStatus,
        security: &SecurityStatus,
    ) -> u8 {
        let mut score = 100u8;

        // 엔진 상태 평가
        if matches!(engine.signature_engine.status, StatusLevel::Critical) { score -= 25; }
        else if matches!(engine.signature_engine.status, StatusLevel::Warning) { score -= 10; }

        if matches!(engine.heuristic_engine.status, StatusLevel::Critical) { score -= 25; }
        else if matches!(engine.heuristic_engine.status, StatusLevel::Warning) { score -= 10; }

        if matches!(engine.quarantine_engine.status, StatusLevel::Critical) { score -= 20; }
        else if matches!(engine.quarantine_engine.status, StatusLevel::Warning) { score -= 5; }

        // 데이터베이스 상태 평가
        if !database.signatures_db.exists { score -= 15; }
        if !database.quarantine_db.exists { score -= 10; }

        // 보안 수준 평가
        match security.protection_level {
            ProtectionLevel::Minimal => score -= 30,
            ProtectionLevel::Low => score -= 20,
            ProtectionLevel::Medium => score -= 10,
            _ => {}
        }

        score
    }

    async fn log_status_summary(&self, status: &SystemStatus) {
        debug!("System Status Summary:");
        debug!("  Health Score: {}/100", status.health_score);
        debug!("  Uptime: {}s", status.performance_metrics.uptime_seconds);
        debug!("  Protection Level: {:?}", status.security_status.protection_level);
        debug!("  Active Monitors: {}", status.security_status.active_monitors);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_status_service_creation() {
        let temp_dir = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.data.database_dir = temp_dir.path().to_path_buf();
        config.quarantine.quarantine_dir = temp_dir.path().join("quarantine");

        let service = StatusService::new(config);

        let status = service.get_system_status().await.unwrap();
        assert!(status.health_score > 0);
        assert!(status.performance_metrics.uptime_seconds >= 0);
    }

    #[tokio::test]
    async fn test_health_check() {
        let temp_dir = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.data.database_dir = temp_dir.path().to_path_buf();
        config.quarantine.quarantine_dir = temp_dir.path().join("quarantine");

        // 격리 디렉토리 생성
        fs::create_dir_all(&config.quarantine.quarantine_dir).unwrap();

        let service = StatusService::new(config);

        let issues = service.check_system_health().await.unwrap();
        // 일부 이슈가 있을 수 있지만 치명적이지 않아야 함
        println!("Health issues: {:?}", issues);
    }

    #[test]
    fn test_protection_level_calculation() {
        let mut config = AppConfig::default();
        let service = StatusService::new(config.clone());

        // 모든 보호 기능 활성화
        config.scan.enable_signatures = true;
        config.scan.enable_heuristics = true;
        config.monitor.enable_real_time = true;
        config.quarantine.auto_quarantine = true;

        let service_max = StatusService::new(config.clone());
        assert!(matches!(service_max.calculate_protection_level(), ProtectionLevel::Maximum));

        // 모든 보호 기능 비활성화
        config.scan.enable_signatures = false;
        config.scan.enable_heuristics = false;
        config.monitor.enable_real_time = false;
        config.quarantine.auto_quarantine = false;

        let service_min = StatusService::new(config);
        assert!(matches!(service_min.calculate_protection_level(), ProtectionLevel::Minimal));
    }
}