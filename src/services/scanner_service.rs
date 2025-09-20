use crate::data::models::{
    config::{AppConfig, ScanConfig},
    scan_result::{ScanError, ScanErrorType, ScanResult, ScanStatus, ScanType},
    threat::{DetectionMethod, Threat, ThreatAction, ThreatSeverity, ThreatType},
};
use crate::engine::detection::signature_scanner::SignatureScanner;
use crate::engine::detection::heuristic_scanner::HeuristicScanner;
use crate::engine::filesystem::file_analyzer::FileAnalyzer;
use crate::error::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;

pub struct ScannerService {
    config: Arc<AppConfig>,
    signature_scanner: Arc<SignatureScanner>,
    heuristic_scanner: Arc<HeuristicScanner>,
    file_analyzer: Arc<FileAnalyzer>,
}

impl ScannerService {
    pub fn new(config: Arc<AppConfig>) -> Self {
        Self {
            signature_scanner: Arc::new(SignatureScanner::new()),
            heuristic_scanner: Arc::new(HeuristicScanner::new()),
            file_analyzer: Arc::new(FileAnalyzer::new()),
            config,
        }
    }

    pub async fn scan_path(&self, path: &Path, scan_config: &ScanConfig) -> Result<ScanResult> {
        info!("Starting scan of path: {}", path.display());
        debug!("Using scanner config: max_threads={}, max_file_size={}",
               self.config.scan.max_threads, self.config.scan.max_file_size);

        let mut result = ScanResult::new(
            if scan_config.max_file_size < 10 * 1024 * 1024 {
                ScanType::Quick
            } else {
                ScanType::Full
            },
            path.to_path_buf(),
        );

        result.status = ScanStatus::Running;

        // 병렬 스캔을 위한 세마포어
        let semaphore = Arc::new(tokio::sync::Semaphore::new(scan_config.max_threads));
        let result_mutex = Arc::new(Mutex::new(result));

        // 파일 목록 수집
        let files = self.collect_files(path, scan_config)?;
        info!("Collected {} files for scanning", files.len());

        // 병렬 스캔 실행
        let mut tasks = Vec::new();

        for file_path in files {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let scanner = self.signature_scanner.clone();
            let heuristic = self.heuristic_scanner.clone();
            let analyzer = self.file_analyzer.clone();
            let result_ref = result_mutex.clone();
            let scan_config = scan_config.clone();

            let task = tokio::spawn(async move {
                let _permit = permit;
                Self::scan_file(file_path, scanner, heuristic, analyzer, result_ref, &scan_config).await
            });

            tasks.push(task);
        }

        // 모든 스캔 작업 완료 대기
        for task in tasks {
            if let Err(e) = task.await {
                error!("Scan task failed: {}", e);
            }
        }

        let mut final_result = result_mutex.lock().await;
        final_result.complete();

        info!(
            "Scan completed: {} files, {} threats found",
            final_result.summary.files_scanned, final_result.summary.threats_found
        );

        Ok(final_result.clone())
    }

    async fn scan_file(
        file_path: PathBuf,
        scanner: Arc<SignatureScanner>,
        heuristic: Arc<HeuristicScanner>,
        analyzer: Arc<FileAnalyzer>,
        result_mutex: Arc<Mutex<ScanResult>>,
        scan_config: &ScanConfig,
    ) {
        debug!("Scanning file: {}", file_path.display());

        // 타임아웃 설정 (30초)
        let timeout_duration = std::time::Duration::from_secs(30);
        let scan_future = Self::scan_file_inner(file_path.clone(), scanner, heuristic, analyzer, result_mutex.clone(), scan_config);

        match tokio::time::timeout(timeout_duration, scan_future).await {
            Ok(_) => {
                debug!("File scan completed: {}", file_path.display());
            }
            Err(_) => {
                warn!("File scan timed out: {}", file_path.display());
                let error = ScanError::new(
                    file_path,
                    ScanErrorType::Timeout,
                    "File scan timed out after 30 seconds".to_string(),
                );
                let mut result = result_mutex.lock().await;
                result.add_error(error);
            }
        }
    }

    async fn scan_file_inner(
        file_path: PathBuf,
        scanner: Arc<SignatureScanner>,
        heuristic: Arc<HeuristicScanner>,
        analyzer: Arc<FileAnalyzer>,
        result_mutex: Arc<Mutex<ScanResult>>,
        scan_config: &ScanConfig,
    ) {

        // 파일 크기 검사
        if let Ok(metadata) = std::fs::metadata(&file_path) {
            if metadata.len() > scan_config.max_file_size {
                let error = ScanError::new(
                    file_path.clone(),
                    ScanErrorType::FileTooBig,
                    format!("File size {} exceeds limit {}", metadata.len(), scan_config.max_file_size),
                );

                let mut result = result_mutex.lock().await;
                result.add_error(error);
                return;
            }

            result_mutex.lock().await.add_scanned_size(metadata.len());
        }

        // 파일 분석
        match analyzer.analyze_file(&file_path).await {
            Ok(analysis) => {
                debug!("File analysis completed for: {}", file_path.display());

                // 시그니처 스캔
                match scanner.scan_file(&file_path, &analysis).await {
                    Ok(scan_results) => {
                        let mut result = result_mutex.lock().await;
                        result.increment_files_scanned();

                        // 위협 발견 시 처리
                        for detection in scan_results {
                            if detection.is_threat {
                                let threat = Threat::new(
                                    detection.signature_name,
                                    ThreatType::Malware, // 실제로는 시그니처에서 결정
                                    ThreatSeverity::Medium, // 실제로는 시그니처에서 결정
                                    file_path.clone(),
                                    analysis.file_hash.clone(),
                                    analysis.file_size,
                                    DetectionMethod::Signature,
                                )
                                .with_description(detection.description)
                                .with_action(ThreatAction::Logged);

                                warn!("Threat detected: {} in {}", threat.name, file_path.display());
                                result.add_threat(threat);
                            }
                        }

                        // 휴리스틱 스캔 추가
                        drop(result); // 뮤텍스 잠금 해제

                        match heuristic.scan_file(&file_path, &analysis).await {
                            Ok(heuristic_results) => {
                                let mut result = result_mutex.lock().await;

                                for heuristic_result in heuristic_results {
                                    if heuristic_result.is_suspicious {
                                        let severity = match heuristic_result.risk_score {
                                            9..=10 => ThreatSeverity::Critical,
                                            7..=8 => ThreatSeverity::High,
                                            5..=6 => ThreatSeverity::Medium,
                                            _ => ThreatSeverity::Low,
                                        };

                                        let threat = Threat::new(
                                            heuristic_result.rule_name,
                                            ThreatType::Suspicious,
                                            severity,
                                            file_path.clone(),
                                            analysis.file_hash.clone(),
                                            analysis.file_size,
                                            DetectionMethod::Heuristic,
                                        )
                                        .with_description(heuristic_result.description)
                                        .with_action(ThreatAction::Logged);

                                        warn!("Heuristic detection: {} in {}", threat.name, file_path.display());
                                        result.add_threat(threat);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to run heuristic scan on {}: {}", file_path.display(), e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to scan file {}: {}", file_path.display(), e);
                        let error = ScanError::new(
                            file_path,
                            ScanErrorType::IOError,
                            e.to_string(),
                        );
                        result_mutex.lock().await.add_error(error);
                    }
                }
            }
            Err(e) => {
                error!("Failed to analyze file {}: {}", file_path.display(), e);
                let error = ScanError::new(
                    file_path,
                    ScanErrorType::IOError,
                    e.to_string(),
                );
                result_mutex.lock().await.add_error(error);
            }
        }
    }

    fn collect_files(&self, path: &Path, scan_config: &ScanConfig) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        if path.is_file() {
            files.push(path.to_path_buf());
            return Ok(files);
        }

        for entry in WalkDir::new(path).follow_links(false) {
            match entry {
                Ok(entry) => {
                    let path = entry.path();

                    if path.is_file() {
                        // 제외 패턴 검사
                        if self.should_exclude(path, &scan_config.exclude_patterns) {
                            continue;
                        }

                        // 포함 패턴 검사
                        if !self.should_include(path, &scan_config.include_patterns) {
                            continue;
                        }

                        files.push(path.to_path_buf());
                    }
                }
                Err(e) => {
                    warn!("Failed to access path during collection: {}", e);
                }
            }
        }

        Ok(files)
    }

    fn should_exclude(&self, path: &Path, exclude_patterns: &[String]) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in exclude_patterns {
            if Self::matches_pattern(&path_str, pattern) {
                debug!("Excluding file {} (matched pattern: {})", path.display(), pattern);
                return true;
            }
        }

        false
    }

    fn should_include(&self, path: &Path, include_patterns: &[String]) -> bool {
        if include_patterns.is_empty() || include_patterns.contains(&"*".to_string()) {
            return true;
        }

        let path_str = path.to_string_lossy();

        for pattern in include_patterns {
            if Self::matches_pattern(&path_str, pattern) {
                return true;
            }
        }

        false
    }

    fn matches_pattern(path: &str, pattern: &str) -> bool {
        // 간단한 glob 패턴 매칭 (실제로는 glob 크레이트 사용 권장)
        if pattern == "*" {
            return true;
        }

        if pattern.starts_with("*.") {
            let extension = &pattern[2..];
            return path.ends_with(&format!(".{}", extension));
        }

        if pattern.contains('*') {
            // 더 복잡한 패턴 매칭 (glob 크레이트 사용 권장)
            let regex_pattern = pattern.replace('*', ".*");
            if let Ok(regex) = regex::Regex::new(&regex_pattern) {
                return regex.is_match(path);
            }
        }

        path.contains(pattern)
    }

    pub async fn scan_file_only(&self, file_path: &Path) -> Result<Vec<Threat>> {
        info!("Scanning single file: {}", file_path.display());

        let analysis = self.file_analyzer.analyze_file(file_path).await?;
        let scan_results = self.signature_scanner.scan_file(file_path, &analysis).await?;

        let threats: Vec<Threat> = scan_results
            .into_iter()
            .filter(|detection| detection.is_threat)
            .map(|detection| {
                Threat::new(
                    detection.signature_name,
                    ThreatType::Malware,
                    ThreatSeverity::Medium,
                    file_path.to_path_buf(),
                    analysis.file_hash.clone(),
                    analysis.file_size,
                    DetectionMethod::Signature,
                )
                .with_description(detection.description)
            })
            .collect();

        Ok(threats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_collect_files() {
        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        std::fs::write(&test_file, "test content").unwrap();

        let config = AppConfig::default();
        let scanner = ScannerService::new(Arc::new(config));

        let files = scanner.collect_files(temp_dir.path(), &ScanConfig::default()).unwrap();
        assert!(!files.is_empty());
    }

    #[test]
    fn test_pattern_matching() {
        assert!(ScannerService::matches_pattern("test.txt", "*.txt"));
        assert!(ScannerService::matches_pattern("path/to/file.exe", "*.exe"));
        assert!(!ScannerService::matches_pattern("test.txt", "*.exe"));
        assert!(ScannerService::matches_pattern("any/path", "*"));
    }
}