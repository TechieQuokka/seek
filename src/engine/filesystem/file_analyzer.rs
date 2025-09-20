use crate::error::Result;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tracing::debug;

#[derive(Debug, Clone)]
pub struct FileAnalysis {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub file_hash: String,
    pub mime_type: String,
    pub is_executable: bool,
    pub entropy: f64,
}

pub struct FileAnalyzer;

impl FileAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub async fn analyze_file(&self, file_path: &Path) -> Result<FileAnalysis> {
        debug!("Analyzing file: {}", file_path.display());

        let metadata = std::fs::metadata(file_path)?;
        let file_size = metadata.len();

        // 파일 해시 계산
        let file_hash = self.calculate_file_hash(file_path).await?;

        // MIME 타입 감지
        let mime_type = self.detect_mime_type(file_path);

        // 실행 파일 여부 확인
        let is_executable = self.is_executable_file(file_path);

        // 엔트로피 계산 (간단한 구현)
        let entropy = self.calculate_entropy(file_path).await.unwrap_or(0.0);

        Ok(FileAnalysis {
            file_path: file_path.to_path_buf(),
            file_size,
            file_hash,
            mime_type,
            is_executable,
            entropy,
        })
    }

    async fn calculate_file_hash(&self, file_path: &Path) -> Result<String> {
        let content = tokio::fs::read(file_path).await?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn detect_mime_type(&self, file_path: &Path) -> String {
        // 확장자 기반 간단한 MIME 타입 감지
        // Use mime_guess for more accurate MIME type detection
        let mime_type = mime_guess::from_path(file_path)
            .first_or_octet_stream()
            .to_string();

        // Override with security-focused MIME types for executable files
        if let Some(extension) = file_path.extension().and_then(|ext| ext.to_str()) {
            match extension.to_lowercase().as_str() {
                "exe" | "msi" | "scr" | "com" | "pif" => "application/x-executable".to_string(),
                "dll" | "sys" => "application/x-sharedlib".to_string(),
                "bat" | "cmd" => "application/x-batch".to_string(),
                "ps1" | "psm1" => "application/x-powershell".to_string(),
                "sh" | "bash" => "application/x-shellscript".to_string(),
                "py" | "pyc" => "application/x-python".to_string(),
                "js" | "jse" => "application/javascript".to_string(),
                "vbs" | "vbe" => "application/x-vbscript".to_string(),
                _ => mime_type,
            }
        } else {
            mime_type
        }
    }

    fn is_executable_file(&self, file_path: &Path) -> bool {
        if let Some(extension) = file_path.extension().and_then(|ext| ext.to_str()) {
            matches!(
                extension.to_lowercase().as_str(),
                "exe" | "msi" | "scr" | "com" | "pif" | "bat" | "cmd" | "ps1" | "sh" | "bash"
            )
        } else {
            // Unix 계열에서는 실행 권한 확인
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = std::fs::metadata(file_path) {
                    let permissions = metadata.permissions();
                    return permissions.mode() & 0o111 != 0;
                }
            }

            false
        }
    }

    async fn calculate_entropy(&self, file_path: &Path) -> Result<f64> {
        use memmap2::MmapOptions;
        use std::fs::File;

        // 파일이 너무 크면 샘플링만 수행
        let metadata = std::fs::metadata(file_path)?;
        let file_size = metadata.len();

        let content = if file_size > 1024 * 1024 {
            // 1MB 이상이면 메모리 매핑을 사용하여 효율적으로 처리
            let file = File::open(file_path)?;
            let mmap = unsafe { MmapOptions::new().map(&file)? };

            // 처음 1MB만 샘플링
            let sample_size = std::cmp::min(1024 * 1024, mmap.len());
            mmap[..sample_size].to_vec()
        } else {
            std::fs::read(file_path)?
        };

        Ok(self.calculate_bytes_entropy(&content))
    }

    fn calculate_bytes_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() || data.len() > 1048576 { // 1MB 제한
            return 0.0;
        }

        let mut counts = [0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let length = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let probability = count as f64 / length;
                // NaN이나 무한대 방지
                if probability > 0.0 && probability.is_finite() {
                    let log_prob = probability.log2();
                    if log_prob.is_finite() {
                        entropy -= probability * log_prob;
                    }
                }
            }
        }

        // 결과값 검증
        if entropy.is_finite() && entropy >= 0.0 {
            entropy
        } else {
            0.0
        }
    }

    pub fn get_file_risk_score(&self, analysis: &FileAnalysis) -> u8 {
        let mut risk_score = 0u8;

        // 실행 파일 여부
        if analysis.is_executable {
            risk_score += 3;
        }

        // 엔트로피 기반 위험도 (높은 엔트로피는 패킹/암호화 의심)
        if analysis.entropy > 7.5 {
            risk_score += 4;
        } else if analysis.entropy > 6.0 {
            risk_score += 2;
        }

        // 파일 크기 (너무 작거나 큰 실행 파일은 의심)
        if analysis.is_executable
            && (analysis.file_size < 1024 || analysis.file_size > 100 * 1024 * 1024) {
                risk_score += 2;
            }

        // MIME 타입 기반 위험도
        match analysis.mime_type.as_str() {
            "application/x-executable" | "application/x-batch" | "application/x-powershell" => {
                risk_score += 2;
            }
            "application/x-vbscript" | "application/javascript" => {
                risk_score += 3;
            }
            _ => {}
        }

        risk_score.min(10) // 최대 10점
    }

    pub async fn extract_strings(&self, file_path: &Path, min_length: usize) -> Result<Vec<String>> {
        let content = tokio::fs::read(file_path).await?;
        let mut strings = Vec::new();
        let mut current_string = String::new();

        for &byte in &content {
            if byte.is_ascii_graphic() || byte == b' ' {
                current_string.push(byte as char);
            } else {
                if current_string.len() >= min_length {
                    strings.push(current_string.clone());
                }
                current_string.clear();
            }
        }

        // 마지막 문자열 처리
        if current_string.len() >= min_length {
            strings.push(current_string);
        }

        Ok(strings)
    }

    pub fn is_suspicious_file_location(&self, file_path: &Path) -> bool {
        let path_str = file_path.to_string_lossy().to_lowercase();

        // 의심스러운 경로 패턴
        let suspicious_patterns = [
            "temp",
            "tmp",
            "appdata\\\\roaming",
            "users\\\\public",
            "programdata",
            "system32", // system32에 일반 실행 파일이 있으면 의심
            "windows\\\\system",
            "%temp%",
            "/tmp/",
            "/var/tmp/",
        ];

        for pattern in &suspicious_patterns {
            if path_str.contains(pattern) {
                return true;
            }
        }

        false
    }
}

impl Default for FileAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[tokio::test]
    async fn test_file_analysis() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Hello, world!").unwrap();

        let analyzer = FileAnalyzer::new();
        let analysis = analyzer.analyze_file(temp_file.path()).await.unwrap();

        assert_eq!(analysis.file_size, 13);
        assert!(!analysis.file_hash.is_empty());
        assert_eq!(analysis.mime_type, "application/octet-stream");
        assert!(!analysis.is_executable);
    }

    #[test]
    fn test_entropy_calculation() {
        let analyzer = FileAnalyzer::new();

        // 균등한 데이터 (높은 엔트로피)
        let uniform_data: Vec<u8> = (0..=255).collect();
        let entropy = analyzer.calculate_bytes_entropy(&uniform_data);
        assert!(entropy > 7.0);

        // 반복되는 데이터 (낮은 엔트로피)
        let repeated_data = vec![0u8; 1000];
        let entropy = analyzer.calculate_bytes_entropy(&repeated_data);
        assert!(entropy < 1.0);
    }

    #[test]
    fn test_mime_type_detection() {
        let analyzer = FileAnalyzer::new();

        assert_eq!(
            analyzer.detect_mime_type(Path::new("test.exe")),
            "application/x-executable"
        );
        assert_eq!(
            analyzer.detect_mime_type(Path::new("script.ps1")),
            "application/x-powershell"
        );
        assert_eq!(
            analyzer.detect_mime_type(Path::new("document.txt")),
            "text/plain"
        );
    }

    #[test]
    fn test_risk_scoring() {
        let analyzer = FileAnalyzer::new();

        let safe_analysis = FileAnalysis {
            file_path: PathBuf::from("document.txt"),
            file_size: 1024,
            file_hash: "hash".to_string(),
            mime_type: "text/plain".to_string(),
            is_executable: false,
            entropy: 4.0,
        };

        let risky_analysis = FileAnalysis {
            file_path: PathBuf::from("suspicious.exe"),
            file_size: 500,
            file_hash: "hash".to_string(),
            mime_type: "application/x-executable".to_string(),
            is_executable: true,
            entropy: 8.0,
        };

        assert!(analyzer.get_file_risk_score(&safe_analysis) < analyzer.get_file_risk_score(&risky_analysis));
    }

    #[test]
    fn test_suspicious_location_detection() {
        let analyzer = FileAnalyzer::new();

        assert!(analyzer.is_suspicious_file_location(Path::new("C:\\\\Users\\\\Public\\\\evil.exe")));
        assert!(analyzer.is_suspicious_file_location(Path::new("/tmp/malware")));
        assert!(!analyzer.is_suspicious_file_location(Path::new("C:\\\\Program Files\\\\app\\\\legitimate.exe")));
    }
}