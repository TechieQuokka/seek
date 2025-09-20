use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub scan: ScanConfig,
    pub monitor: MonitorConfig,
    pub quarantine: QuarantineConfig,
    pub logging: LoggingConfig,
    pub signature: SignatureConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub max_threads: usize,
    pub max_file_size: u64, // bytes
    pub timeout: u64,       // seconds
    pub exclude_patterns: Vec<String>,
    pub include_patterns: Vec<String>,
    pub scan_archives: bool,
    pub scan_memory: bool,
    pub heuristic_enabled: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_threads: num_cpus::get(),
            max_file_size: 100 * 1024 * 1024, // 100MB
            timeout: 300, // 5 minutes
            exclude_patterns: vec![
                "*.tmp".to_string(),
                "*.log".to_string(),
                ".git/*".to_string(),
                "target/*".to_string(),
            ],
            include_patterns: vec!["*".to_string()],
            scan_archives: true,
            scan_memory: false,
            heuristic_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub enabled: bool,
    pub watch_paths: Vec<PathBuf>,
    pub exclude_paths: Vec<PathBuf>,
    pub real_time_scan: bool,
    pub quarantine_on_detect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    pub directory: PathBuf,
    pub max_size: u64,    // bytes
    pub retention_days: u32,
    pub encrypt: bool,
    pub compress: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_path: Option<PathBuf>,
    pub max_file_size: u64,
    pub max_files: u32,
    pub console_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureConfig {
    pub database_path: PathBuf,
    pub auto_update: bool,
    pub update_interval: u32, // hours
    pub custom_rules_path: Option<PathBuf>,
    pub yara_enabled: bool,
    pub clamav_enabled: bool,
    pub virustotal_enabled: bool,
    pub virustotal_api_key: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            scan: ScanConfig {
                max_threads: num_cpus::get(),
                max_file_size: 100 * 1024 * 1024, // 100MB
                timeout: 300, // 5 minutes
                exclude_patterns: vec![
                    "*.tmp".to_string(),
                    "*.log".to_string(),
                    ".git/*".to_string(),
                    "target/*".to_string(),
                ],
                include_patterns: vec!["*".to_string()],
                scan_archives: true,
                scan_memory: false,
                heuristic_enabled: true,
            },
            monitor: MonitorConfig {
                enabled: false,
                watch_paths: vec![std::env::current_dir().unwrap_or_default()],
                exclude_paths: vec![],
                real_time_scan: true,
                quarantine_on_detect: true,
            },
            quarantine: QuarantineConfig {
                directory: PathBuf::from("quarantine"),
                max_size: 1024 * 1024 * 1024, // 1GB
                retention_days: 30,
                encrypt: true,
                compress: true,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                file_path: Some(PathBuf::from("logs/seek.log")),
                max_file_size: 10 * 1024 * 1024, // 10MB
                max_files: 10,
                console_output: true,
            },
            signature: SignatureConfig {
                database_path: PathBuf::from("signatures"),
                auto_update: true,
                update_interval: 24, // 24 hours
                custom_rules_path: None,
                yara_enabled: false,
                clamav_enabled: false,
                virustotal_enabled: false,
                virustotal_api_key: None,
            },
        }
    }
}