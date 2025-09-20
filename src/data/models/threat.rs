use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub id: String,
    pub name: String,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub file_path: PathBuf,
    pub file_hash: String,
    pub file_size: u64,
    pub detected_at: DateTime<Utc>,
    pub detection_method: DetectionMethod,
    pub description: Option<String>,
    pub action_taken: ThreatAction,
    pub quarantine_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatType {
    Virus,
    Trojan,
    Malware,
    Adware,
    Spyware,
    Rootkit,
    Worm,
    Ransomware,
    Suspicious,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionMethod {
    Signature,
    Heuristic,
    Yara,
    ClamAV,
    VirusTotal,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatAction {
    None,
    Logged,
    Quarantined,
    Deleted,
    Cleaned,
    AccessDenied,
}

impl Threat {
    pub fn new(
        name: String,
        threat_type: ThreatType,
        severity: ThreatSeverity,
        file_path: PathBuf,
        file_hash: String,
        file_size: u64,
        detection_method: DetectionMethod,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            threat_type,
            severity,
            file_path,
            file_hash,
            file_size,
            detected_at: Utc::now(),
            detection_method,
            description: None,
            action_taken: ThreatAction::None,
            quarantine_path: None,
        }
    }

    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    pub fn with_action(mut self, action: ThreatAction) -> Self {
        self.action_taken = action;
        self
    }

    pub fn with_quarantine_path(mut self, path: PathBuf) -> Self {
        self.quarantine_path = Some(path);
        self
    }
}

impl std::fmt::Display for ThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatType::Virus => write!(f, "Virus"),
            ThreatType::Trojan => write!(f, "Trojan"),
            ThreatType::Malware => write!(f, "Malware"),
            ThreatType::Adware => write!(f, "Adware"),
            ThreatType::Spyware => write!(f, "Spyware"),
            ThreatType::Rootkit => write!(f, "Rootkit"),
            ThreatType::Worm => write!(f, "Worm"),
            ThreatType::Ransomware => write!(f, "Ransomware"),
            ThreatType::Suspicious => write!(f, "Suspicious"),
            ThreatType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatSeverity::Low => write!(f, "Low"),
            ThreatSeverity::Medium => write!(f, "Medium"),
            ThreatSeverity::High => write!(f, "High"),
            ThreatSeverity::Critical => write!(f, "Critical"),
        }
    }
}

impl std::fmt::Display for DetectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionMethod::Signature => write!(f, "Signature"),
            DetectionMethod::Heuristic => write!(f, "Heuristic"),
            DetectionMethod::Yara => write!(f, "Yara"),
            DetectionMethod::ClamAV => write!(f, "ClamAV"),
            DetectionMethod::VirusTotal => write!(f, "VirusTotal"),
            DetectionMethod::Custom(name) => write!(f, "Custom({})", name),
        }
    }
}