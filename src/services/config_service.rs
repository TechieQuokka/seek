use crate::data::models::config::AppConfig;
use crate::error::{Error, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};

pub struct ConfigService {
    config_path: PathBuf,
    backup_path: PathBuf,
}

impl ConfigService {
    pub fn new(config_path: PathBuf) -> Self {
        let backup_path = config_path.with_extension("toml.backup");

        Self {
            config_path,
            backup_path,
        }
    }

    pub async fn show_config(&self) -> Result<AppConfig> {
        self.load_config().await
    }

    pub async fn set_config_value(&self, key: &str, value: &str) -> Result<()> {
        let mut config = self.load_config().await?;

        // 백업 생성
        self.create_backup().await?;

        // 키-값 설정
        match self.set_nested_value(&mut config, key, value) {
            Ok(_) => {
                self.save_config(&config).await?;
                info!("Configuration updated: {} = {}", key, value);
                Ok(())
            }
            Err(e) => {
                error!("Failed to set configuration: {}", e);
                Err(e)
            }
        }
    }

    pub async fn reset_config(&self) -> Result<()> {
        // 백업 생성
        self.create_backup().await?;

        // 기본 설정으로 재설정
        let default_config = AppConfig::default();
        self.save_config(&default_config).await?;

        info!("Configuration reset to default values");
        Ok(())
    }

    pub async fn export_config(&self, output_path: &PathBuf) -> Result<()> {
        let config = self.load_config().await?;
        let config_content = toml::to_string_pretty(&config)?;

        fs::write(output_path, config_content)?;
        info!("Configuration exported to: {}", output_path.display());
        Ok(())
    }

    pub async fn import_config(&self, input_path: &PathBuf) -> Result<()> {
        if !input_path.exists() {
            return Err(Error::Config(format!(
                "Configuration file not found: {}",
                input_path.display()
            )));
        }

        // 백업 생성
        self.create_backup().await?;

        // 새 설정 로드 및 검증
        let content = fs::read_to_string(input_path)?;
        let new_config: AppConfig = toml::from_str(&content)?;

        // 설정 유효성 검증
        self.validate_config(&new_config)?;

        // 설정 저장
        self.save_config(&new_config).await?;

        info!("Configuration imported from: {}", input_path.display());
        Ok(())
    }

    pub async fn get_config_value(&self, key: &str) -> Result<String> {
        let config = self.load_config().await?;
        self.get_nested_value(&config, key)
    }

    pub async fn list_all_settings(&self) -> Result<HashMap<String, String>> {
        let config = self.load_config().await?;
        let mut settings = HashMap::new();

        // 설정을 JSON으로 변환 후 flat map으로 변환
        let config_json = serde_json::to_value(&config)?;
        self.flatten_json("", &config_json, &mut settings);

        Ok(settings)
    }

    pub async fn validate_current_config(&self) -> Result<Vec<String>> {
        let config = self.load_config().await?;
        let mut issues = Vec::new();

        // 기본 유효성 검사
        if config.scan.max_threads == 0 {
            issues.push("scan.max_threads cannot be 0".to_string());
        }

        if config.scan.max_file_size == 0 {
            issues.push("scan.max_file_size cannot be 0".to_string());
        }

        if !config.quarantine.directory.exists() {
            issues.push(format!(
                "quarantine.directory does not exist: {}",
                config.quarantine.directory.display()
            ));
        }

        if !config.signature.database_path.exists() {
            issues.push(format!(
                "signature.database_path does not exist: {}",
                config.signature.database_path.display()
            ));
        }

        if config.scan.timeout == 0 {
            issues.push("scan.timeout cannot be 0".to_string());
        }

        Ok(issues)
    }

    pub async fn restore_from_backup(&self) -> Result<bool> {
        if self.backup_path.exists() {
            fs::copy(&self.backup_path, &self.config_path)?;
            info!("Configuration restored from backup");
            Ok(true)
        } else {
            warn!("No backup file found");
            Ok(false)
        }
    }

    async fn load_config(&self) -> Result<AppConfig> {
        if !self.config_path.exists() {
            // 기본 설정 생성
            let default_config = AppConfig::default();
            self.save_config(&default_config).await?;
            return Ok(default_config);
        }

        let content = fs::read_to_string(&self.config_path)?;
        let config: AppConfig = toml::from_str(&content)?;
        Ok(config)
    }

    async fn save_config(&self, config: &AppConfig) -> Result<()> {
        let content = toml::to_string_pretty(config)?;

        // 부모 디렉토리 생성
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&self.config_path, content)?;
        Ok(())
    }

    async fn create_backup(&self) -> Result<()> {
        if self.config_path.exists() {
            fs::copy(&self.config_path, &self.backup_path)?;
            debug!("Configuration backup created");
        }
        Ok(())
    }

    fn set_nested_value(&self, config: &mut AppConfig, key: &str, value: &str) -> Result<()> {
        let parts: Vec<&str> = key.split('.').collect();

        match parts.as_slice() {
            ["scan", "max_threads"] => {
                config.scan.max_threads = value.parse()
                    .map_err(|_| Error::Config(format!("Invalid number: {}", value)))?;
            }
            ["scan", "max_file_size"] => {
                config.scan.max_file_size = value.parse()
                    .map_err(|_| Error::Config(format!("Invalid number: {}", value)))?;
            }
            ["scan", "timeout"] => {
                config.scan.timeout = value.parse()
                    .map_err(|_| Error::Config(format!("Invalid number: {}", value)))?;
            }
            ["scan", "heuristic_enabled"] => {
                config.scan.heuristic_enabled = value.parse()
                    .map_err(|_| Error::Config(format!("Invalid boolean: {}", value)))?;
            }
            ["scan", "scan_archives"] => {
                config.scan.scan_archives = value.parse()
                    .map_err(|_| Error::Config(format!("Invalid boolean: {}", value)))?;
            }
            ["quarantine", "directory"] => {
                config.quarantine.directory = PathBuf::from(value);
            }
            ["quarantine", "encrypt"] => {
                config.quarantine.encrypt = value.parse()
                    .map_err(|_| Error::Config(format!("Invalid boolean: {}", value)))?;
            }
            ["signature", "database_path"] => {
                config.signature.database_path = PathBuf::from(value);
            }
            ["monitor", "enabled"] => {
                config.monitor.enabled = value.parse()
                    .map_err(|_| Error::Config(format!("Invalid boolean: {}", value)))?;
            }
            ["logging", "level"] => {
                config.logging.level = value.to_string();
            }
            ["logging", "console_output"] => {
                config.logging.console_output = value.parse()
                    .map_err(|_| Error::Config(format!("Invalid boolean: {}", value)))?;
            }
            _ => {
                return Err(Error::Config(format!("Unknown configuration key: {}", key)));
            }
        }

        Ok(())
    }

    fn get_nested_value(&self, config: &AppConfig, key: &str) -> Result<String> {
        let parts: Vec<&str> = key.split('.').collect();

        let value = match parts.as_slice() {
            ["scan", "max_threads"] => config.scan.max_threads.to_string(),
            ["scan", "max_file_size"] => config.scan.max_file_size.to_string(),
            ["scan", "timeout"] => config.scan.timeout.to_string(),
            ["scan", "heuristic_enabled"] => config.scan.heuristic_enabled.to_string(),
            ["scan", "scan_archives"] => config.scan.scan_archives.to_string(),
            ["quarantine", "directory"] => config.quarantine.directory.display().to_string(),
            ["quarantine", "encrypt"] => config.quarantine.encrypt.to_string(),
            ["signature", "database_path"] => config.signature.database_path.display().to_string(),
            ["monitor", "enabled"] => config.monitor.enabled.to_string(),
            ["logging", "level"] => config.logging.level.clone(),
            ["logging", "console_output"] => config.logging.console_output.to_string(),
            _ => {
                return Err(Error::Config(format!("Unknown configuration key: {}", key)));
            }
        };

        Ok(value)
    }

    fn flatten_json(&self, prefix: &str, value: &Value, result: &mut HashMap<String, String>) {
        match value {
            Value::Object(map) => {
                for (key, val) in map {
                    let new_prefix = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", prefix, key)
                    };
                    self.flatten_json(&new_prefix, val, result);
                }
            }
            Value::Array(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    let new_prefix = format!("{}[{}]", prefix, i);
                    self.flatten_json(&new_prefix, val, result);
                }
            }
            _ => {
                let string_value = match value {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    _ => value.to_string(),
                };
                result.insert(prefix.to_string(), string_value);
            }
        }
    }

    fn validate_config(&self, config: &AppConfig) -> Result<()> {
        // 기본 유효성 검사
        if config.scan.max_threads == 0 {
            return Err(Error::Config("scan.max_threads cannot be 0".to_string()));
        }

        if config.scan.max_file_size == 0 {
            return Err(Error::Config("scan.max_file_size cannot be 0".to_string()));
        }

        if config.scan.timeout == 0 {
            return Err(Error::Config("scan.timeout cannot be 0".to_string()));
        }

        // 로깅 레벨 검증
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&config.logging.level.as_str()) {
            return Err(Error::Config(format!(
                "Invalid logging level: {}. Valid levels: {:?}",
                config.logging.level, valid_levels
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_config_service_creation() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        let service = ConfigService::new(config_path.clone());
        assert_eq!(service.config_path, config_path);
    }

    #[tokio::test]
    async fn test_config_operations() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("config.toml");

        let service = ConfigService::new(config_path);

        // 기본 설정 로드
        let config = service.show_config().await.unwrap();
        assert!(config.scan.max_threads > 0);

        // 설정 값 변경
        service.set_config_value("scan.max_threads", "8").await.unwrap();

        // 변경된 값 확인
        let new_value = service.get_config_value("scan.max_threads").await.unwrap();
        assert_eq!(new_value, "8");

        // 설정 검증
        let issues = service.validate_current_config().await.unwrap();
        // 디렉토리가 존재하지 않을 수 있으므로 경고만 확인
        println!("Validation issues: {:?}", issues);
    }

    #[tokio::test]
    async fn test_config_export_import() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        let export_path = temp_dir.path().join("exported_config.toml");

        let service = ConfigService::new(config_path);

        // 설정 내보내기
        service.export_config(&export_path).await.unwrap();
        assert!(export_path.exists());

        // 설정 값 변경
        service.set_config_value("scan.max_threads", "16").await.unwrap();

        // 설정 가져오기 (이전 값으로 복원)
        service.import_config(&export_path).await.unwrap();

        // 복원 확인
        let restored_value = service.get_config_value("scan.max_threads").await.unwrap();
        // 기본값으로 복원되었는지 확인
        assert_ne!(restored_value, "16");
    }
}