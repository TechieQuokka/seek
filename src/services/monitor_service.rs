use crate::cli::args::MonitorStartArgs;
use crate::cli::output::OutputFormatter;
use crate::data::models::config::AppConfig;
use crate::error::Result;
use crate::services::scanner_service::ScannerService;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

pub struct MonitorService {
    config: Arc<AppConfig>,
    scanner_service: Arc<ScannerService>,
    is_monitoring: Arc<AtomicBool>,
    logs: Arc<Mutex<Vec<String>>>,
}

impl MonitorService {
    pub fn new(config: Arc<AppConfig>) -> Self {
        Self {
            scanner_service: Arc::new(ScannerService::new(config.clone())),
            is_monitoring: Arc::new(AtomicBool::new(false)),
            logs: Arc::new(Mutex::new(Vec::new())),
            config,
        }
    }

    pub async fn start_monitoring(
        &self,
        path: PathBuf,
        args: MonitorStartArgs,
    ) -> Result<()> {
        if self.is_monitoring.load(Ordering::SeqCst) {
            OutputFormatter::print_warning("Monitoring is already active");
            return Ok(());
        }

        self.is_monitoring.store(true, Ordering::SeqCst);
        self.add_log("Monitoring started").await;

        let (tx, mut rx) = tokio::sync::mpsc::channel(1000);
        let _path_clone = path.clone();

        // 파일 시스템 감시자 생성
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            match res {
                Ok(event) => {
                    if let Err(e) = tx.blocking_send(event) {
                        eprintln!("Failed to send event: {}", e);
                    }
                }
                Err(e) => eprintln!("Watch error: {:?}", e),
            }
        })?;

        // 감시 시작
        watcher.watch(&path, RecursiveMode::Recursive)?;
        info!("Started monitoring path: {}", path.display());

        let scanner = self.scanner_service.clone();
        let is_monitoring = self.is_monitoring.clone();
        let logs = self.logs.clone();
        let _scan_config = self.config.scan.clone();

        // 이벤트 처리 루프
        while let Some(event) = rx.recv().await {
            if !is_monitoring.load(Ordering::SeqCst) {
                break;
            }

            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    for path in event.paths {
                        if path.is_file() {
                            // 제외 패턴 검사
                            if self.should_exclude_file(&path, &args.exclude) {
                                continue;
                            }

                            debug!("File changed: {}", path.display());

                            // 짧은 지연 (파일 쓰기 완료 대기)
                            tokio::time::sleep(Duration::from_millis(500)).await;

                            // 파일 스캔
                            match scanner.scan_file_only(&path).await {
                                Ok(threats) => {
                                    if !threats.is_empty() {
                                        let msg = format!(
                                            "🦠 THREAT DETECTED in {}: {} threats found",
                                            path.display(),
                                            threats.len()
                                        );

                                        OutputFormatter::print_error(&msg);
                                        Self::add_log_static(&logs, &msg).await;

                                        // 위협 세부 정보 출력
                                        for threat in threats {
                                            let threat_msg = format!(
                                                "  - {}: {} ({})",
                                                threat.name,
                                                threat.threat_type,
                                                threat.severity
                                            );
                                            OutputFormatter::print_warning(&threat_msg);
                                            Self::add_log_static(&logs, &threat_msg).await;
                                        }

                                        // 알림 처리 (향후 구현)
                                        if let Some(_alert_method) = &args.alert {
                                            // TODO: 이메일, 데스크톱 알림 등
                                        }
                                    } else {
                                        let msg = format!("✅ File scanned clean: {}", path.display());
                                        debug!("{}", msg);
                                        Self::add_log_static(&logs, &msg).await;
                                    }
                                }
                                Err(e) => {
                                    let msg = format!("❌ Failed to scan {}: {}", path.display(), e);
                                    warn!("{}", msg);
                                    Self::add_log_static(&logs, &msg).await;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        self.is_monitoring.store(false, Ordering::SeqCst);
        self.add_log("Monitoring stopped").await;
        Ok(())
    }

    pub async fn stop_monitoring(&self) -> Result<()> {
        self.is_monitoring.store(false, Ordering::SeqCst);
        self.add_log("Stop monitoring requested").await;
        Ok(())
    }

    pub async fn is_monitoring_active(&self) -> Result<bool> {
        Ok(self.is_monitoring.load(Ordering::SeqCst))
    }

    pub async fn get_recent_logs(&self, count: usize) -> Result<Vec<String>> {
        let logs = self.logs.lock().await;
        let start = if logs.len() > count {
            logs.len() - count
        } else {
            0
        };
        Ok(logs[start..].to_vec())
    }

    pub async fn follow_logs(&self) -> Result<()> {
        let mut last_count = 0;
        let logs = self.logs.clone();

        loop {
            {
                let current_logs = logs.lock().await;
                if current_logs.len() > last_count {
                    for log in &current_logs[last_count..] {
                        println!("{}", log);
                    }
                    last_count = current_logs.len();
                }
            }

            tokio::time::sleep(Duration::from_millis(1000)).await;

            // Ctrl+C 감지를 위한 기본적인 구현
            if !self.is_monitoring.load(Ordering::SeqCst) {
                break;
            }
        }

        Ok(())
    }

    async fn add_log(&self, message: &str) {
        Self::add_log_static(&self.logs, message).await;
    }

    async fn add_log_static(logs: &Arc<Mutex<Vec<String>>>, message: &str) {
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let log_entry = format!("[{}] {}", timestamp, message);

        let mut logs = logs.lock().await;
        logs.push(log_entry);

        // 로그 크기 제한 (최대 1000개)
        if logs.len() > 1000 {
            logs.drain(0..500); // 절반 제거
        }
    }

    fn should_exclude_file(&self, path: &Path, exclude_patterns: &[String]) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in exclude_patterns {
            if self.matches_pattern(&path_str, pattern) {
                return true;
            }
        }

        // 기본 제외 패턴
        let default_excludes = [
            "*.tmp", "*.log", "*.cache", "*~", "*.swp", "*.lock",
            ".git/*", "node_modules/*", "target/*", "build/*"
        ];

        for pattern in &default_excludes {
            if self.matches_pattern(&path_str, pattern) {
                return true;
            }
        }

        false
    }

    fn matches_pattern(&self, path: &str, pattern: &str) -> bool {
        // 간단한 글롭 패턴 매칭
        if pattern.starts_with("*.") {
            let extension = &pattern[2..];
            return path.ends_with(&format!(".{}", extension));
        }

        if pattern.contains('*') {
            let regex_pattern = pattern.replace('*', ".*");
            if let Ok(regex) = regex::Regex::new(&regex_pattern) {
                return regex.is_match(path);
            }
        }

        path.contains(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        let config = Arc::new(AppConfig::default());
        let service = MonitorService::new(config);

        assert!(service.matches_pattern("test.tmp", "*.tmp"));
        assert!(service.matches_pattern("path/to/file.log", "*.log"));
        assert!(!service.matches_pattern("test.txt", "*.tmp"));
    }

    #[tokio::test]
    async fn test_logging() {
        let config = Arc::new(AppConfig::default());
        let service = MonitorService::new(config);

        service.add_log("Test message").await;
        let logs = service.get_recent_logs(10).await.unwrap();

        assert!(!logs.is_empty());
        assert!(logs[0].contains("Test message"));
    }
}