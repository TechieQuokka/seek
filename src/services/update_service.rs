use crate::data::models::config::AppConfig;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub version: String,
    pub signature_count: usize,
    pub last_updated: u64,
    pub source: String,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureDatabase {
    pub info: UpdateInfo,
    pub signatures: Vec<SignatureEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEntry {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub threat_type: String,
    pub severity: String,
    pub description: Option<String>,
    pub added_date: u64,
}

pub struct UpdateService {
    #[allow(dead_code)]
    config: AppConfig,
    database_path: PathBuf,
    #[allow(dead_code)]
    signatures_path: PathBuf,
}

impl UpdateService {
    pub fn new(config: AppConfig) -> Result<Self> {
        let database_path = config.signature.database_path.join("signatures.db");
        let signatures_path = config.signature.database_path.join("signatures");

        // 시그니처 디렉토리 생성
        if !signatures_path.exists() {
            fs::create_dir_all(&signatures_path)?;
            info!("Created signatures directory: {}", signatures_path.display());
        }

        Ok(Self {
            config,
            database_path,
            signatures_path,
        })
    }

    pub async fn check_for_updates(&self) -> Result<Option<UpdateInfo>> {
        info!("Checking for signature database updates...");

        // 현재 버전 정보 로드
        let current_info = self.load_current_info().await?;

        // 간단한 업데이트 시뮬레이션 (실제 환경에서는 외부 서버와 통신)
        let latest_info = self.fetch_latest_info().await?;

        if latest_info.version != current_info.version {
            info!("New update available: {} -> {}", current_info.version, latest_info.version);
            Ok(Some(latest_info))
        } else {
            info!("Signature database is up to date (version: {})", current_info.version);
            Ok(None)
        }
    }

    pub async fn download_updates(&self, force: bool) -> Result<bool> {
        info!("Downloading signature database updates...");

        if !force {
            // 업데이트 체크
            if let Some(_update_info) = self.check_for_updates().await? {
                info!("Update available, proceeding with download...");
            } else {
                info!("No updates available, skipping download");
                return Ok(false);
            }
        }

        // 새로운 시그니처 데이터베이스 생성 (데모용)
        let new_signatures = self.generate_signature_database().await?;

        // 백업 생성
        self.backup_current_database().await?;

        // 새 데이터베이스 저장
        self.save_signature_database(&new_signatures).await?;

        info!("Signature database updated successfully");
        Ok(true)
    }

    pub async fn get_current_info(&self) -> Result<UpdateInfo> {
        self.load_current_info().await
    }

    pub async fn get_signature_stats(&self) -> Result<(usize, u64)> {
        let database = self.load_signature_database().await?;
        let total_signatures = database.signatures.len();
        let last_updated = database.info.last_updated;
        Ok((total_signatures, last_updated))
    }

    pub async fn add_custom_signature(&self, signature: SignatureEntry) -> Result<()> {
        let mut database = self.load_signature_database().await?;

        // 중복 체크
        if database.signatures.iter().any(|s| s.id == signature.id) {
            return Err(Error::Database(format!(
                "Signature with ID '{}' already exists",
                signature.id
            )));
        }

        database.signatures.push(signature);
        database.info.signature_count = database.signatures.len();
        database.info.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.save_signature_database(&database).await?;
        info!("Custom signature added successfully");
        Ok(())
    }

    pub async fn remove_signature(&self, signature_id: &str) -> Result<bool> {
        let mut database = self.load_signature_database().await?;

        let initial_len = database.signatures.len();
        database.signatures.retain(|s| s.id != signature_id);

        if database.signatures.len() < initial_len {
            database.info.signature_count = database.signatures.len();
            database.info.last_updated = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            self.save_signature_database(&database).await?;
            info!("Signature '{}' removed successfully", signature_id);
            Ok(true)
        } else {
            warn!("Signature '{}' not found", signature_id);
            Ok(false)
        }
    }

    pub async fn list_signatures(&self, filter: Option<&str>) -> Result<Vec<SignatureEntry>> {
        let database = self.load_signature_database().await?;

        if let Some(filter_text) = filter {
            let filtered = database.signatures
                .into_iter()
                .filter(|s| {
                    s.name.contains(filter_text) ||
                    s.threat_type.contains(filter_text) ||
                    s.pattern.contains(filter_text)
                })
                .collect();
            Ok(filtered)
        } else {
            Ok(database.signatures)
        }
    }

    async fn load_current_info(&self) -> Result<UpdateInfo> {
        if !self.database_path.exists() {
            // 기본 정보 생성
            return Ok(UpdateInfo {
                version: "1.0.0".to_string(),
                signature_count: 0,
                last_updated: 0,
                source: "builtin".to_string(),
                checksum: "none".to_string(),
            });
        }

        let database = self.load_signature_database().await?;
        Ok(database.info)
    }

    async fn load_signature_database(&self) -> Result<SignatureDatabase> {
        if !self.database_path.exists() {
            // 기본 데이터베이스 생성
            return Ok(self.generate_signature_database().await?);
        }

        let content = fs::read_to_string(&self.database_path)?;
        let database: SignatureDatabase = serde_json::from_str(&content)?;
        Ok(database)
    }

    async fn save_signature_database(&self, database: &SignatureDatabase) -> Result<()> {
        let content = serde_json::to_string_pretty(database)?;
        fs::write(&self.database_path, content)?;
        Ok(())
    }

    async fn fetch_latest_info(&self) -> Result<UpdateInfo> {
        // 실제 환경에서는 외부 서버에서 최신 정보를 가져옴
        // 여기서는 데모용으로 시뮬레이션
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(UpdateInfo {
            version: "1.0.1".to_string(),
            signature_count: 150,
            last_updated: current_time,
            source: "official".to_string(),
            checksum: "abc123def456".to_string(),
        })
    }

    async fn generate_signature_database(&self) -> Result<SignatureDatabase> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signatures = vec![
            SignatureEntry {
                id: "EICAR-001".to_string(),
                name: "EICAR Test String".to_string(),
                pattern: r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE\!\$H\+H\*".to_string(),
                threat_type: "test".to_string(),
                severity: "low".to_string(),
                description: Some("EICAR antivirus test file".to_string()),
                added_date: current_time,
            },
            SignatureEntry {
                id: "MALWARE-001".to_string(),
                name: "Generic PowerShell Downloader".to_string(),
                pattern: r"(?i)(powershell.*-encodedcommand|iex.*downloadstring|invoke-expression)".to_string(),
                threat_type: "trojan".to_string(),
                severity: "high".to_string(),
                description: Some("Detects PowerShell-based downloaders".to_string()),
                added_date: current_time,
            },
            SignatureEntry {
                id: "RANSOM-001".to_string(),
                name: "Ransomware File Extensions".to_string(),
                pattern: r"\.(encrypt|locked|crypt|vault|axx|xyz|zzz)$".to_string(),
                threat_type: "ransomware".to_string(),
                severity: "critical".to_string(),
                description: Some("Detects common ransomware file extensions".to_string()),
                added_date: current_time,
            },
            SignatureEntry {
                id: "SCRIPT-001".to_string(),
                name: "Suspicious VBScript".to_string(),
                pattern: r"(?i)(wscript\.shell|shell\.application|createobject.*shell)".to_string(),
                threat_type: "script".to_string(),
                severity: "medium".to_string(),
                description: Some("Detects potentially malicious VBScript patterns".to_string()),
                added_date: current_time,
            },
            SignatureEntry {
                id: "DROPPER-001".to_string(),
                name: "File Dropper Behavior".to_string(),
                pattern: r"(?i)(temp.*\.exe|appdata.*\.exe|system32.*\.tmp)".to_string(),
                threat_type: "dropper".to_string(),
                severity: "high".to_string(),
                description: Some("Detects file dropper patterns".to_string()),
                added_date: current_time,
            },
        ];

        let info = UpdateInfo {
            version: "1.0.1".to_string(),
            signature_count: signatures.len(),
            last_updated: current_time,
            source: "builtin".to_string(),
            checksum: "generated".to_string(),
        };

        Ok(SignatureDatabase { info, signatures })
    }

    async fn backup_current_database(&self) -> Result<()> {
        if self.database_path.exists() {
            let backup_path = self.database_path.with_extension("db.backup");
            fs::copy(&self.database_path, &backup_path)?;
            info!("Database backed up to: {}", backup_path.display());
        }
        Ok(())
    }

    pub async fn restore_from_backup(&self) -> Result<bool> {
        let backup_path = self.database_path.with_extension("db.backup");

        if backup_path.exists() {
            fs::copy(&backup_path, &self.database_path)?;
            info!("Database restored from backup");
            Ok(true)
        } else {
            warn!("No backup file found");
            Ok(false)
        }
    }

    pub async fn validate_database(&self) -> Result<bool> {
        match self.load_signature_database().await {
            Ok(database) => {
                // 기본 유효성 검사
                if database.signatures.is_empty() {
                    warn!("Signature database is empty");
                    return Ok(false);
                }

                // 중복 ID 검사
                let mut ids = std::collections::HashSet::new();
                for signature in &database.signatures {
                    if !ids.insert(&signature.id) {
                        error!("Duplicate signature ID found: {}", signature.id);
                        return Ok(false);
                    }
                }

                info!("Signature database validation passed ({} signatures)", database.signatures.len());
                Ok(true)
            }
            Err(e) => {
                error!("Database validation failed: {}", e);
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_update_service_creation() {
        let temp_dir = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.data.database_dir = temp_dir.path().to_path_buf();

        let service = UpdateService::new(config).unwrap();
        assert!(service.signatures_path.exists());
    }

    #[tokio::test]
    async fn test_signature_database_operations() {
        let temp_dir = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.data.database_dir = temp_dir.path().to_path_buf();

        let service = UpdateService::new(config).unwrap();

        // 데이터베이스 생성
        let generated_db = service.generate_signature_database().await.unwrap();
        service.save_signature_database(&generated_db).await.unwrap();

        // 데이터베이스 로드
        let loaded_db = service.load_signature_database().await.unwrap();
        assert_eq!(loaded_db.signatures.len(), generated_db.signatures.len());

        // 시그니처 추가
        let new_signature = SignatureEntry {
            id: "TEST-001".to_string(),
            name: "Test Signature".to_string(),
            pattern: "test_pattern".to_string(),
            threat_type: "test".to_string(),
            severity: "low".to_string(),
            description: Some("Test signature".to_string()),
            added_date: 0,
        };

        service.add_custom_signature(new_signature).await.unwrap();

        // 시그니처 목록 확인
        let signatures = service.list_signatures(None).await.unwrap();
        assert!(signatures.iter().any(|s| s.id == "TEST-001"));

        // 시그니처 제거
        let removed = service.remove_signature("TEST-001").await.unwrap();
        assert!(removed);

        // 제거 확인
        let signatures = service.list_signatures(None).await.unwrap();
        assert!(!signatures.iter().any(|s| s.id == "TEST-001"));
    }

    #[tokio::test]
    async fn test_database_validation() {
        let temp_dir = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.data.database_dir = temp_dir.path().to_path_buf();

        let service = UpdateService::new(config).unwrap();

        // 기본 데이터베이스 생성
        service.download_updates(true).await.unwrap();

        // 유효성 검사
        let is_valid = service.validate_database().await.unwrap();
        assert!(is_valid);
    }
}