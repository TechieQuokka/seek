use crate::data::models::config::AppConfig;
use crate::error::{Error, Result};
use std::path::Path;

/// 설정 파일을 로드합니다
pub fn load_config() -> Result<AppConfig> {
    // 우선순위: CLI 지정 > 환경변수 > 기본 위치
    let config_path = std::env::var("SEEK_CONFIG")
        .unwrap_or_else(|_| "config/default.toml".to_string());

    if Path::new(&config_path).exists() {
        load_config_from_file(&config_path)
    } else {
        // 기본 설정 사용
        Ok(AppConfig::default())
    }
}

/// 파일에서 설정을 로드합니다
pub fn load_config_from_file(path: &str) -> Result<AppConfig> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("Failed to read config file {}: {}", path, e)))?;

    let config: AppConfig = toml::from_str(&content)
        .map_err(|e| Error::Config(format!("Failed to parse config file {}: {}", path, e)))?;

    Ok(config)
}