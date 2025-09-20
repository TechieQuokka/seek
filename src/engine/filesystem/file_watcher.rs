use crate::error::Result;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
// use std::time::Duration;
use tracing::{debug, error, info, warn};

/// 파일 시스템 변경 이벤트 타입
#[derive(Debug, Clone)]
pub enum FileEvent {
    Created(PathBuf),
    Modified(PathBuf),
    Deleted(PathBuf),
    Renamed { from: PathBuf, to: PathBuf },
}

/// 파일 시스템 감시기
pub struct FileWatcher {
    watcher: Option<RecommendedWatcher>,
    event_receiver: Option<Receiver<notify::Result<Event>>>,
    is_watching: bool,
}

impl FileWatcher {
    /// 새로운 파일 감시기 인스턴스 생성
    pub fn new() -> Result<Self> {
        Ok(Self {
            watcher: None,
            event_receiver: None,
            is_watching: false,
        })
    }

    /// 지정된 경로에서 파일 변경 감시 시작
    pub fn start_watching<P: AsRef<Path>>(&mut self, path: P) -> Result<Receiver<FileEvent>> {
        let (event_tx, event_rx) = mpsc::channel();

        // notify 감시기 생성
        let mut watcher = notify::recommended_watcher(move |res| {
            if let Err(e) = event_tx.send(res) {
                error!("Failed to send file event: {}", e);
            }
        })?;

        // 감시 시작
        watcher.watch(path.as_ref(), RecursiveMode::Recursive)?;
        info!("Started watching path: {}", path.as_ref().display());

        self.watcher = Some(watcher);
        self.event_receiver = Some(event_rx);
        self.is_watching = true;

        // 이벤트 처리 스레드 시작
        let (file_event_tx, file_event_rx) = mpsc::channel();
        let event_receiver = self.event_receiver.take().unwrap();

        thread::spawn(move || {
            Self::process_events(event_receiver, file_event_tx);
        });

        Ok(file_event_rx)
    }

    /// 파일 변경 감시 중지
    pub fn stop_watching(&mut self) -> Result<()> {
        if self.is_watching {
            self.watcher.take();
            self.event_receiver.take();
            self.is_watching = false;
            info!("Stopped file watching");
        }
        Ok(())
    }

    /// 감시 상태 확인
    pub fn is_watching(&self) -> bool {
        self.is_watching
    }

    /// 이벤트 처리 (내부 메서드)
    fn process_events(
        event_receiver: Receiver<notify::Result<Event>>,
        file_event_sender: Sender<FileEvent>,
    ) {
        debug!("Started file event processing thread");

        for event_result in event_receiver {
            match event_result {
                Ok(event) => {
                    if let Some(file_event) = Self::convert_event(event) {
                        if let Err(e) = file_event_sender.send(file_event) {
                            error!("Failed to send file event: {}", e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    warn!("File watch error: {}", e);
                }
            }
        }

        debug!("File event processing thread terminated");
    }

    /// notify 이벤트를 내부 FileEvent로 변환
    fn convert_event(event: Event) -> Option<FileEvent> {
        match event.kind {
            EventKind::Create(_) => {
                if let Some(path) = event.paths.first() {
                    debug!("File created: {}", path.display());
                    Some(FileEvent::Created(path.clone()))
                } else {
                    None
                }
            }
            EventKind::Modify(_) => {
                if let Some(path) = event.paths.first() {
                    debug!("File modified: {}", path.display());
                    Some(FileEvent::Modified(path.clone()))
                } else {
                    None
                }
            }
            EventKind::Remove(_) => {
                if let Some(path) = event.paths.first() {
                    debug!("File deleted: {}", path.display());
                    Some(FileEvent::Deleted(path.clone()))
                } else {
                    None
                }
            }
            EventKind::Other => {
                // 이름 변경 이벤트의 경우
                if event.paths.len() >= 2 {
                    debug!("File renamed: {} -> {}", event.paths[0].display(), event.paths[1].display());
                    Some(FileEvent::Renamed {
                        from: event.paths[0].clone(),
                        to: event.paths[1].clone(),
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// 특정 파일 확장자 필터링
    pub fn should_scan_file(path: &Path, allowed_extensions: &[&str]) -> bool {
        if allowed_extensions.is_empty() {
            return true; // 필터가 없으면 모든 파일 허용
        }

        if let Some(extension) = path.extension() {
            if let Some(ext_str) = extension.to_str() {
                return allowed_extensions.iter().any(|&allowed| {
                    ext_str.eq_ignore_ascii_case(allowed)
                });
            }
        }

        false
    }

    /// 파일 크기 제한 확인
    pub fn should_scan_file_size(path: &Path, max_size: u64) -> bool {
        match std::fs::metadata(path) {
            Ok(metadata) => metadata.len() <= max_size,
            Err(e) => {
                warn!("Failed to get file metadata for {}: {}", path.display(), e);
                false
            }
        }
    }

    /// 파일이 스캔 가능한지 종합 검사
    pub fn is_scannable_file(
        path: &Path,
        allowed_extensions: &[&str],
        max_size: Option<u64>,
        exclude_patterns: &[String],
    ) -> bool {
        // 제외 패턴 확인
        let path_str = path.to_string_lossy();
        for pattern in exclude_patterns {
            if path_str.contains(pattern) {
                debug!("File excluded by pattern '{}': {}", pattern, path.display());
                return false;
            }
        }

        // 확장자 확인
        if !Self::should_scan_file(path, allowed_extensions) {
            debug!("File excluded by extension: {}", path.display());
            return false;
        }

        // 크기 확인
        if let Some(max_size) = max_size {
            if !Self::should_scan_file_size(path, max_size) {
                debug!("File excluded by size: {}", path.display());
                return false;
            }
        }

        // 파일 접근 가능성 확인
        if !path.exists() || !path.is_file() {
            debug!("File not accessible: {}", path.display());
            return false;
        }

        true
    }
}

impl Drop for FileWatcher {
    fn drop(&mut self) {
        if self.is_watching {
            let _ = self.stop_watching();
        }
    }
}