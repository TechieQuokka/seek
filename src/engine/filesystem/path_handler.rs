use crate::error::{Error, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// 경로 처리 및 정규화를 담당하는 유틸리티
pub struct PathHandler;

impl PathHandler {
    /// 경로를 정규화하고 절대 경로로 변환
    pub fn normalize_path<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
        let path = path.as_ref();

        // 경로가 존재하는지 확인
        if !path.exists() {
            return Err(Error::Other(format!("Path does not exist: {}", path.display())));
        }

        // 절대 경로로 변환
        let canonical_path = path.canonicalize()
            .map_err(|e| Error::Other(format!("Failed to canonicalize path {}: {}", path.display(), e)))?;

        debug!("Normalized path: {} -> {}", path.display(), canonical_path.display());
        Ok(canonical_path)
    }

    /// 심볼릭 링크 처리
    pub fn resolve_symlink<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
        let path = path.as_ref();

        if path.is_symlink() {
            match fs::read_link(path) {
                Ok(target) => {
                    debug!("Resolved symlink: {} -> {}", path.display(), target.display());

                    // 상대 경로인 경우 절대 경로로 변환
                    if target.is_relative() {
                        if let Some(parent) = path.parent() {
                            Ok(parent.join(target))
                        } else {
                            Ok(target)
                        }
                    } else {
                        Ok(target)
                    }
                }
                Err(e) => {
                    warn!("Failed to read symlink {}: {}", path.display(), e);
                    Ok(path.to_path_buf())
                }
            }
        } else {
            Ok(path.to_path_buf())
        }
    }

    /// 경로가 안전한지 검증 (예: 상위 디렉토리 탈출 시도 등)
    pub fn is_safe_path<P: AsRef<Path>>(path: P, base_path: P) -> bool {
        let path = path.as_ref();
        let base_path = base_path.as_ref();

        // 절대 경로로 변환하여 비교
        match (path.canonicalize(), base_path.canonicalize()) {
            (Ok(canonical_path), Ok(canonical_base)) => {
                canonical_path.starts_with(canonical_base)
            }
            _ => {
                // canonicalize 실패 시 문자열 기반으로 기본 검사
                let path_str = path.to_string_lossy();
                let base_str = base_path.to_string_lossy();

                // 상위 디렉토리 탈출 패턴 검사
                !path_str.contains("..") && path_str.starts_with(base_str.as_ref())
            }
        }
    }

    /// 경로에 대한 읽기 권한 확인
    pub fn has_read_permission<P: AsRef<Path>>(path: P) -> bool {
        let path = path.as_ref();

        match fs::metadata(path) {
            Ok(metadata) => {
                // 기본적인 읽기 가능성 검사
                !metadata.permissions().readonly() || path.is_file()
            }
            Err(e) => {
                debug!("Cannot access metadata for {}: {}", path.display(), e);
                false
            }
        }
    }

    /// 경로에 대한 쓰기 권한 확인
    pub fn has_write_permission<P: AsRef<Path>>(path: P) -> bool {
        let path = path.as_ref();

        if path.exists() {
            match fs::metadata(path) {
                Ok(metadata) => !metadata.permissions().readonly(),
                Err(_) => false,
            }
        } else {
            // 파일이 존재하지 않는 경우, 부모 디렉토리에 쓰기 권한이 있는지 확인
            if let Some(parent) = path.parent() {
                Self::has_write_permission(parent)
            } else {
                false
            }
        }
    }

    /// 파일 크기 제한 검사
    pub fn check_file_size<P: AsRef<Path>>(path: P, max_size: u64) -> Result<bool> {
        let path = path.as_ref();

        if !path.is_file() {
            return Ok(true); // 디렉토리는 크기 제한 없음
        }

        match fs::metadata(path) {
            Ok(metadata) => {
                let size = metadata.len();
                Ok(size <= max_size)
            }
            Err(e) => Err(Error::Other(format!("Failed to get file size for {}: {}", path.display(), e))),
        }
    }

    /// 경로가 숨김 파일인지 확인
    pub fn is_hidden_file<P: AsRef<Path>>(path: P) -> bool {
        let path = path.as_ref();

        if let Some(file_name) = path.file_name() {
            if let Some(name_str) = file_name.to_str() {
                return name_str.starts_with('.');
            }
        }

        false
    }

    /// 시스템 파일인지 확인 (Windows)
    #[cfg(windows)]
    pub fn is_system_file<P: AsRef<Path>>(path: P) -> bool {
        use std::os::windows::fs::MetadataExt;

        let path = path.as_ref();

        match fs::metadata(path) {
            Ok(metadata) => {
                const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
                const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;

                let attributes = metadata.file_attributes();
                (attributes & FILE_ATTRIBUTE_SYSTEM) != 0 || (attributes & FILE_ATTRIBUTE_HIDDEN) != 0
            }
            Err(_) => false,
        }
    }

    /// 시스템 파일인지 확인 (Unix)
    #[cfg(unix)]
    pub fn is_system_file<P: AsRef<Path>>(path: P) -> bool {
        let path = path.as_ref();

        // Unix에서는 주로 경로 기반으로 시스템 파일 판단
        let path_str = path.to_string_lossy();
        path_str.starts_with("/sys/")
            || path_str.starts_with("/proc/")
            || path_str.starts_with("/dev/")
            || Self::is_hidden_file(path)
    }

    /// 임시 파일인지 확인
    pub fn is_temp_file<P: AsRef<Path>>(path: P) -> bool {
        let path = path.as_ref();

        if let Some(extension) = path.extension() {
            if let Some(ext_str) = extension.to_str() {
                let temp_extensions = ["tmp", "temp", "bak", "cache", "log"];
                return temp_extensions.iter().any(|&ext| ext_str.eq_ignore_ascii_case(ext));
            }
        }

        // 경로에 temp 디렉토리가 포함되어 있는지 확인
        let path_str = path.to_string_lossy().to_lowercase();
        path_str.contains("temp") || path_str.contains("tmp") || path_str.contains("cache")
    }

    /// 실행 파일인지 확인
    pub fn is_executable<P: AsRef<Path>>(path: P) -> bool {
        let path = path.as_ref();

        if let Some(extension) = path.extension() {
            if let Some(ext_str) = extension.to_str() {
                let executable_extensions = [
                    "exe", "dll", "sys", "com", "bat", "cmd", "ps1", "vbs", "js",
                    "scr", "msi", "jar", "app", "deb", "rpm", "dmg", "pkg"
                ];
                return executable_extensions.iter().any(|&ext| ext_str.eq_ignore_ascii_case(ext));
            }
        }

        // Unix 계열에서는 실행 권한 확인
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(path) {
                return metadata.permissions().mode() & 0o111 != 0;
            }
        }

        false
    }

    /// 압축 파일인지 확인
    pub fn is_archive<P: AsRef<Path>>(path: P) -> bool {
        let path = path.as_ref();

        if let Some(extension) = path.extension() {
            if let Some(ext_str) = extension.to_str() {
                let archive_extensions = [
                    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "lz4", "lzma",
                    "cab", "iso", "img", "dmg", "pkg", "deb", "rpm"
                ];
                return archive_extensions.iter().any(|&ext| ext_str.eq_ignore_ascii_case(ext));
            }
        }

        false
    }

    /// 경로 깊이 계산
    pub fn calculate_depth<P: AsRef<Path>>(path: P, base_path: P) -> Option<usize> {
        let path = path.as_ref();
        let base_path = base_path.as_ref();

        match path.strip_prefix(base_path) {
            Ok(relative_path) => Some(relative_path.components().count()),
            Err(_) => None,
        }
    }

    /// 안전한 파일명 생성 (특수 문자 제거)
    pub fn sanitize_filename(filename: &str) -> String {
        let invalid_chars = ['<', '>', ':', '"', '|', '?', '*', '/', '\\'];

        filename
            .chars()
            .map(|c| if invalid_chars.contains(&c) || c.is_control() { '_' } else { c })
            .collect()
    }

    /// 경로에서 상대 경로 부분 추출
    pub fn get_relative_path<P: AsRef<Path>>(path: P, base: P) -> Result<PathBuf> {
        let path = path.as_ref();
        let base = base.as_ref();

        path.strip_prefix(base)
            .map(|p| p.to_path_buf())
            .map_err(|_| Error::Other(format!(
                "Path {} is not under base path {}",
                path.display(),
                base.display()
            )))
    }

    /// 파일 확장자가 허용된 목록에 있는지 확인
    pub fn is_allowed_extension<P: AsRef<Path>>(path: P, allowed_extensions: &[&str]) -> bool {
        if allowed_extensions.is_empty() {
            return true; // 빈 목록이면 모든 확장자 허용
        }

        let path = path.as_ref();
        if let Some(extension) = path.extension() {
            if let Some(ext_str) = extension.to_str() {
                return allowed_extensions.iter().any(|&allowed| {
                    ext_str.eq_ignore_ascii_case(allowed)
                });
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_is_safe_path() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();
        let safe_path = base_path.join("safe_file.txt");
        let unsafe_path = base_path.join("../unsafe_file.txt");

        // 안전한 경로
        assert!(PathHandler::is_safe_path(&safe_path, base_path));

        // 안전하지 않은 경로 (상위 디렉토리 탈출)
        assert!(!PathHandler::is_safe_path(&unsafe_path, base_path));
    }

    #[test]
    fn test_is_executable() {
        assert!(PathHandler::is_executable(Path::new("test.exe")));
        assert!(PathHandler::is_executable(Path::new("script.bat")));
        assert!(PathHandler::is_executable(Path::new("app.jar")));
        assert!(!PathHandler::is_executable(Path::new("document.txt")));
        assert!(!PathHandler::is_executable(Path::new("image.jpg")));
    }

    #[test]
    fn test_is_archive() {
        assert!(PathHandler::is_archive(Path::new("archive.zip")));
        assert!(PathHandler::is_archive(Path::new("backup.tar.gz")));
        assert!(PathHandler::is_archive(Path::new("installer.msi")));
        assert!(!PathHandler::is_archive(Path::new("document.txt")));
        assert!(!PathHandler::is_archive(Path::new("script.exe")));
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(PathHandler::sanitize_filename("normal_file.txt"), "normal_file.txt");
        assert_eq!(PathHandler::sanitize_filename("file<with>invalid:chars"), "file_with_invalid_chars");
        assert_eq!(PathHandler::sanitize_filename("file|with\"quotes"), "file_with_quotes");
    }

    #[test]
    fn test_is_allowed_extension() {
        let allowed = vec!["txt", "exe", "dll"];

        assert!(PathHandler::is_allowed_extension(Path::new("file.txt"), &allowed));
        assert!(PathHandler::is_allowed_extension(Path::new("file.EXE"), &allowed)); // 대소문자 무시
        assert!(!PathHandler::is_allowed_extension(Path::new("file.jpg"), &allowed));

        // 빈 목록은 모든 확장자 허용
        assert!(PathHandler::is_allowed_extension(Path::new("file.anything"), &[]));
    }

    #[test]
    fn test_calculate_depth() {
        let base = Path::new("/base");
        let path1 = Path::new("/base/file.txt");
        let path2 = Path::new("/base/dir/subdir/file.txt");
        let path3 = Path::new("/other/file.txt");

        assert_eq!(PathHandler::calculate_depth(path1, base), Some(1));
        assert_eq!(PathHandler::calculate_depth(path2, base), Some(3));
        assert_eq!(PathHandler::calculate_depth(path3, base), None);
    }
}