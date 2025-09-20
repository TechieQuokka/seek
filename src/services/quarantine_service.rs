use crate::data::models::{
    config::AppConfig,
    threat::Threat,
};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedFile {
    pub id: String,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub file_name: String,
    pub file_size: u64,
    pub quarantine_time: u64,
    pub threat_info: Threat,
    pub sha256_hash: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuarantineDatabase {
    pub files: HashMap<String, QuarantinedFile>,
    pub stats: QuarantineStats,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuarantineStats {
    pub total_files: usize,
    pub total_size: u64,
    pub last_cleanup: u64,
}

pub struct QuarantineService {
    #[allow(dead_code)]
    config: AppConfig,
    quarantine_dir: PathBuf,
    database_path: PathBuf,
}

impl QuarantineService {
    pub fn new(config: AppConfig) -> Result<Self> {
        let quarantine_dir = config.quarantine.directory.clone();
        let database_path = quarantine_dir.join("quarantine.db");

        // 격리 디렉토리 생성
        if !quarantine_dir.exists() {
            fs::create_dir_all(&quarantine_dir)?;
            info!("Created quarantine directory: {}", quarantine_dir.display());
        }

        Ok(Self {
            config,
            quarantine_dir,
            database_path,
        })
    }

    pub async fn quarantine_file(&self, file_path: &Path, threat: Threat) -> Result<String> {
        if !file_path.exists() {
            return Err(Error::Quarantine(format!(
                "File not found: {}",
                file_path.display()
            )));
        }

        let file_id = Uuid::new_v4().to_string();
        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        // 격리 파일 경로 생성 (원본 확장자 제거 + .quarantine 추가)
        let quarantine_file_name = format!("{}.quarantine", file_id);
        let quarantine_path = self.quarantine_dir.join(&quarantine_file_name);

        // 파일 메타데이터 수집
        let metadata = fs::metadata(file_path)?;
        let file_size = metadata.len();

        // 파일 해시 계산
        let file_content = fs::read(file_path)?;
        let sha256_hash = self.calculate_sha256(&file_content);

        // 파일 암호화 및 이동
        let encrypted_content = self.encrypt_file(&file_content, &file_id)?;
        fs::write(&quarantine_path, encrypted_content)?;

        // 원본 파일 삭제
        fs::remove_file(file_path)?;

        // 격리 정보 생성
        let quarantined_file = QuarantinedFile {
            id: file_id.clone(),
            original_path: file_path.to_path_buf(),
            quarantine_path,
            file_name,
            file_size,
            quarantine_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            threat_info: threat,
            sha256_hash,
            metadata: HashMap::new(),
        };

        // 데이터베이스에 추가
        self.add_to_database(quarantined_file).await?;

        info!("File quarantined successfully: {} -> {}", file_path.display(), file_id);
        Ok(file_id)
    }

    pub async fn restore_file(&self, file_id: &str) -> Result<PathBuf> {
        let mut database = self.load_database().await?;

        let quarantined_file = database.files.get(file_id).ok_or_else(|| {
            Error::Quarantine(format!("Quarantined file not found: {}", file_id))
        })?;

        // 원본 경로가 이미 존재하는지 확인
        if quarantined_file.original_path.exists() {
            return Err(Error::Quarantine(format!(
                "Original path already exists: {}",
                quarantined_file.original_path.display()
            )));
        }

        // 격리 파일 읽기 및 복호화
        let encrypted_content = fs::read(&quarantined_file.quarantine_path)?;
        let decrypted_content = self.decrypt_file(&encrypted_content, file_id)?;

        // 원본 디렉토리 생성 (필요한 경우)
        if let Some(parent) = quarantined_file.original_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // 원본 경로로 복원
        fs::write(&quarantined_file.original_path, decrypted_content)?;

        // 격리 파일 삭제
        fs::remove_file(&quarantined_file.quarantine_path)?;

        // 데이터베이스에서 제거
        let original_path = quarantined_file.original_path.clone();
        database.files.remove(file_id);
        database.stats.total_files = database.files.len();
        database.stats.total_size = database.files.values().map(|f| f.file_size).sum();

        self.save_database(&database).await?;

        info!("File restored successfully: {} -> {}", file_id, original_path.display());
        Ok(original_path)
    }

    pub async fn delete_quarantined_file(&self, file_id: &str) -> Result<()> {
        let mut database = self.load_database().await?;

        let quarantined_file = database.files.get(file_id).ok_or_else(|| {
            Error::Quarantine(format!("Quarantined file not found: {}", file_id))
        })?;

        // 격리 파일 삭제
        if quarantined_file.quarantine_path.exists() {
            fs::remove_file(&quarantined_file.quarantine_path)?;
        }

        // 데이터베이스에서 제거
        database.files.remove(file_id);
        database.stats.total_files = database.files.len();
        database.stats.total_size = database.files.values().map(|f| f.file_size).sum();

        self.save_database(&database).await?;

        info!("Quarantined file deleted permanently: {}", file_id);
        Ok(())
    }

    pub async fn list_quarantined_files(&self) -> Result<Vec<QuarantinedFile>> {
        let database = self.load_database().await?;
        Ok(database.files.values().cloned().collect())
    }

    pub async fn get_quarantined_file(&self, file_id: &str) -> Result<QuarantinedFile> {
        let database = self.load_database().await?;
        database.files.get(file_id).cloned().ok_or_else(|| {
            Error::Quarantine(format!("Quarantined file not found: {}", file_id))
        })
    }

    pub async fn cleanup_old_files(&self, max_age_days: u32) -> Result<usize> {
        let mut database = self.load_database().await?;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let max_age_seconds = max_age_days as u64 * 24 * 60 * 60;

        let mut removed_count = 0;
        let mut files_to_remove = Vec::new();

        for (file_id, quarantined_file) in &database.files {
            if current_time - quarantined_file.quarantine_time > max_age_seconds {
                files_to_remove.push(file_id.clone());
            }
        }

        for file_id in files_to_remove {
            if let Some(quarantined_file) = database.files.get(&file_id) {
                if quarantined_file.quarantine_path.exists() {
                    if let Err(e) = fs::remove_file(&quarantined_file.quarantine_path) {
                        warn!("Failed to remove old quarantine file {}: {}", file_id, e);
                        continue;
                    }
                }
                database.files.remove(&file_id);
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            database.stats.total_files = database.files.len();
            database.stats.total_size = database.files.values().map(|f| f.file_size).sum();
            database.stats.last_cleanup = current_time;
            self.save_database(&database).await?;
        }

        info!("Cleanup completed: {} old files removed", removed_count);
        Ok(removed_count)
    }

    pub async fn get_quarantine_stats(&self) -> Result<QuarantineStats> {
        let database = self.load_database().await?;
        Ok(database.stats)
    }

    async fn load_database(&self) -> Result<QuarantineDatabase> {
        if !self.database_path.exists() {
            return Ok(QuarantineDatabase {
                files: HashMap::new(),
                stats: QuarantineStats {
                    total_files: 0,
                    total_size: 0,
                    last_cleanup: 0,
                },
            });
        }

        let content = fs::read_to_string(&self.database_path)?;
        let database: QuarantineDatabase = serde_json::from_str(&content)?;
        Ok(database)
    }

    async fn save_database(&self, database: &QuarantineDatabase) -> Result<()> {
        let content = serde_json::to_string_pretty(database)?;
        fs::write(&self.database_path, content)?;
        Ok(())
    }

    async fn add_to_database(&self, quarantined_file: QuarantinedFile) -> Result<()> {
        let mut database = self.load_database().await?;

        database.files.insert(quarantined_file.id.clone(), quarantined_file);
        database.stats.total_files = database.files.len();
        database.stats.total_size = database.files.values().map(|f| f.file_size).sum();

        self.save_database(&database).await?;
        Ok(())
    }

    fn encrypt_file(&self, content: &[u8], key: &str) -> Result<Vec<u8>> {
        // 간단한 XOR 암호화 (실제 환경에서는 AES 등 사용 권장)
        let key_bytes = key.as_bytes();
        let mut encrypted = Vec::with_capacity(content.len());

        for (i, &byte) in content.iter().enumerate() {
            let key_byte = key_bytes[i % key_bytes.len()];
            encrypted.push(byte ^ key_byte);
        }

        Ok(encrypted)
    }

    fn decrypt_file(&self, encrypted_content: &[u8], key: &str) -> Result<Vec<u8>> {
        // XOR 암호화는 복호화도 동일한 과정
        self.encrypt_file(encrypted_content, key)
    }

    fn calculate_sha256(&self, content: &[u8]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // 실제 환경에서는 SHA256 해시 라이브러리 사용 권장
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_quarantine_service_creation() {
        let temp_dir = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.quarantine.quarantine_dir = temp_dir.path().to_path_buf();

        let service = QuarantineService::new(config).unwrap();
        assert!(service.quarantine_dir.exists());
    }

    #[tokio::test]
    async fn test_quarantine_and_restore_file() {
        let temp_dir = tempdir().unwrap();
        let mut config = AppConfig::default();
        config.quarantine.quarantine_dir = temp_dir.path().join("quarantine");

        let service = QuarantineService::new(config).unwrap();

        // 테스트 파일 생성
        let test_file = temp_dir.path().join("test_malware.txt");
        fs::write(&test_file, b"malicious content").unwrap();

        // 위협 정보 생성
        let threat = Threat {
            name: "Test Malware".to_string(),
            threat_type: "Test".to_string(),
            severity: ThreatSeverity::High,
            description: Some("Test threat".to_string()),
            file_path: test_file.clone(),
            detection_method: "signature".to_string(),
            risk_score: 85,
            metadata: HashMap::new(),
        };

        // 격리
        let file_id = service.quarantine_file(&test_file, threat).await.unwrap();
        assert!(!test_file.exists());

        // 복원
        let restored_path = service.restore_file(&file_id).await.unwrap();
        assert!(restored_path.exists());
        assert_eq!(fs::read_to_string(&restored_path).unwrap(), "malicious content");
    }
}