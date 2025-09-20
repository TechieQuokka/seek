use crate::data::models::threat::Threat;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: String,
    pub scan_type: ScanType,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration: Option<Duration>,
    pub target_path: PathBuf,
    pub summary: ScanSummary,
    pub threats: Vec<Threat>,
    pub errors: Vec<ScanError>,
    pub status: ScanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanType {
    Quick,
    Full,
    Custom,
    Realtime,
    Scheduled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub files_scanned: u64,
    pub directories_scanned: u64,
    pub threats_found: u64,
    pub threats_quarantined: u64,
    pub threats_cleaned: u64,
    pub threats_deleted: u64,
    pub files_skipped: u64,
    pub errors_encountered: u64,
    pub total_size_scanned: u64, // bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub file_path: PathBuf,
    pub error_type: ScanErrorType,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanErrorType {
    AccessDenied,
    FileNotFound,
    FileTooBig,
    CorruptedFile,
    Timeout,
    MemoryError,
    IOError,
    UnknownError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanStatus {
    Running,
    Completed,
    Cancelled,
    Failed,
    Paused,
}

impl ScanResult {
    pub fn new(scan_type: ScanType, target_path: PathBuf) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            scan_type,
            start_time: Utc::now(),
            end_time: None,
            duration: None,
            target_path,
            summary: ScanSummary::default(),
            threats: Vec::new(),
            errors: Vec::new(),
            status: ScanStatus::Running,
        }
    }

    pub fn complete(&mut self) {
        self.end_time = Some(Utc::now());
        self.duration = Some(
            self.end_time
                .unwrap()
                .signed_duration_since(self.start_time)
                .to_std()
                .unwrap_or_default(),
        );
        self.status = ScanStatus::Completed;
    }

    pub fn add_threat(&mut self, threat: Threat) {
        self.threats.push(threat);
        self.summary.threats_found += 1;
    }

    pub fn add_error(&mut self, error: ScanError) {
        self.errors.push(error);
        self.summary.errors_encountered += 1;
    }

    pub fn increment_files_scanned(&mut self) {
        self.summary.files_scanned += 1;
    }

    pub fn increment_directories_scanned(&mut self) {
        self.summary.directories_scanned += 1;
    }

    pub fn add_scanned_size(&mut self, size: u64) {
        self.summary.total_size_scanned += size;
    }
}

impl Default for ScanSummary {
    fn default() -> Self {
        Self {
            files_scanned: 0,
            directories_scanned: 0,
            threats_found: 0,
            threats_quarantined: 0,
            threats_cleaned: 0,
            threats_deleted: 0,
            files_skipped: 0,
            errors_encountered: 0,
            total_size_scanned: 0,
        }
    }
}

impl ScanError {
    pub fn new(file_path: PathBuf, error_type: ScanErrorType, message: String) -> Self {
        Self {
            file_path,
            error_type,
            message,
            timestamp: Utc::now(),
        }
    }
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Quick => write!(f, "Quick Scan"),
            ScanType::Full => write!(f, "Full Scan"),
            ScanType::Custom => write!(f, "Custom Scan"),
            ScanType::Realtime => write!(f, "Real-time Scan"),
            ScanType::Scheduled => write!(f, "Scheduled Scan"),
        }
    }
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStatus::Running => write!(f, "Running"),
            ScanStatus::Completed => write!(f, "Completed"),
            ScanStatus::Cancelled => write!(f, "Cancelled"),
            ScanStatus::Failed => write!(f, "Failed"),
            ScanStatus::Paused => write!(f, "Paused"),
        }
    }
}