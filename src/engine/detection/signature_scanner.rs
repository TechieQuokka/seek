use crate::engine::filesystem::file_analyzer::FileAnalysis;
use crate::error::Result;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub signature_name: String,
    pub is_threat: bool,
    pub confidence: f32,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub name: String,
    pub hash: String,
    pub pattern: Option<String>,
    pub description: String,
    pub threat_level: u8,
}

pub struct SignatureScanner {
    signatures: HashMap<String, Signature>,
    pattern_signatures: Vec<Signature>,
}

impl SignatureScanner {
    pub fn new() -> Self {
        let mut scanner = Self {
            signatures: HashMap::new(),
            pattern_signatures: Vec::new(),
        };

        scanner.load_default_signatures();
        scanner
    }

    pub async fn scan_file(
        &self,
        file_path: &Path,
        analysis: &FileAnalysis,
    ) -> Result<Vec<DetectionResult>> {
        debug!("Running signature scan for: {}", file_path.display());

        let mut results = Vec::new();

        // 해시 기반 시그니처 검사
        if let Some(signature) = self.signatures.get(&analysis.file_hash) {
            results.push(DetectionResult {
                signature_name: signature.name.clone(),
                is_threat: true,
                confidence: 1.0,
                description: format!("Known malware: {}", signature.description),
            });
            info!("Hash-based detection: {} for {}", signature.name, file_path.display());
        }

        // EICAR 파일 직접 검사 (최우선 처리)
        if let Ok(content) = std::fs::read(file_path) {
            if content.len() < 1024 { // 작은 파일만 직접 검사
                let eicar_signature = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
                if content.windows(eicar_signature.len()).any(|window| window == eicar_signature) {
                    results.push(DetectionResult {
                        signature_name: "EICAR-Test-File".to_string(),
                        is_threat: true,
                        confidence: 1.0,
                        description: "EICAR antivirus test file detected".to_string(),
                    });
                    info!("EICAR test file detected: {}", file_path.display());
                    return Ok(results); // EICAR 발견 시 즉시 반환
                }
            }
        }

        // 패턴 기반 시그니처 검사 (메모리 매핑을 사용하여 효율적인 파일 처리)
        if let Ok(file) = std::fs::File::open(file_path) {
            if file.metadata().map_or(false, |m| m.len() <= 10485760) { // 10MB 제한
                if let Ok(mmap) = unsafe { memmap2::MmapOptions::new().map(&file) } {
                    for signature in &self.pattern_signatures {
                        if let Some(pattern) = &signature.pattern {
                            if self.check_pattern(&*mmap, pattern) {
                                results.push(DetectionResult {
                                    signature_name: signature.name.clone(),
                                    is_threat: true,
                                    confidence: 0.8,
                                    description: format!("Pattern match: {}", signature.description),
                                });
                                info!("Pattern-based detection: {} for {}", signature.name, file_path.display());
                            }
                        }
                    }
                }
            }
        }

        // 안전한 파일인 경우
        if results.is_empty() {
            results.push(DetectionResult {
                signature_name: "Clean".to_string(),
                is_threat: false,
                confidence: 0.9,
                description: "No threats detected".to_string(),
            });
        }

        Ok(results)
    }

    fn check_pattern(&self, content: &[u8], pattern: &str) -> bool {
        // 간단한 바이트 패턴 매칭
        if pattern.starts_with("hex:") {
            let hex_pattern = &pattern[4..];
            if let Ok(pattern_bytes) = hex::decode(hex_pattern) {
                return content.windows(pattern_bytes.len()).any(|window| window == pattern_bytes);
            }
        }

        // 문자열 패턴 매칭
        if pattern.starts_with("string:") {
            let string_pattern = &pattern[7..];
            return content.windows(string_pattern.len()).any(|window| {
                std::str::from_utf8(window).map_or(false, |s| s == string_pattern)
            });
        }

        // 정규표현식 패턴 (간단한 구현) - 크기 제한 추가
        if content.len() <= 1048576 { // 1MB 제한
            if let Ok(content_str) = std::str::from_utf8(content) {
                if let Ok(regex) = regex::Regex::new(pattern) {
                    return regex.is_match(content_str);
                }
            }
        }

        false
    }

    fn load_default_signatures(&mut self) {
        // 테스트용 기본 시그니처 로드
        info!("Loading default virus signatures");

        // 알려진 악성 파일 해시 (예시)
        let test_signatures = vec![
            Signature {
                name: "EICAR-Test-File".to_string(),
                hash: self.calculate_eicar_hash(),
                pattern: None,
                description: "EICAR antivirus test file".to_string(),
                threat_level: 1,
            },
            Signature {
                name: "Suspicious-PowerShell".to_string(),
                hash: String::new(),
                pattern: Some("powershell.*-encodedcommand".to_string()),
                description: "Suspicious PowerShell command execution".to_string(),
                threat_level: 3,
            },
            Signature {
                name: "Potential-Malware-1".to_string(),
                hash: String::new(),
                pattern: Some("hex:4d5a.*50450000".to_string()), // PE header pattern
                description: "Potential malware with suspicious PE structure".to_string(),
                threat_level: 2,
            },
        ];

        for signature in test_signatures {
            if signature.hash.is_empty() {
                self.pattern_signatures.push(signature);
            } else {
                self.signatures.insert(signature.hash.clone(), signature);
            }
        }

        info!("Loaded {} hash signatures and {} pattern signatures",
               self.signatures.len(), self.pattern_signatures.len());
    }

    fn calculate_eicar_hash(&self) -> String {
        // EICAR 테스트 파일 해시 계산
        let eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let mut hasher = Sha256::new();
        hasher.update(eicar_content);
        format!("{:x}", hasher.finalize())
    }

    pub fn add_signature(&mut self, signature: Signature) {
        if signature.hash.is_empty() {
            self.pattern_signatures.push(signature);
        } else {
            self.signatures.insert(signature.hash.clone(), signature);
        }
    }

    pub fn load_signatures_from_file(&mut self, path: &Path) -> Result<()> {
        info!("Loading signatures from file: {}", path.display());

        let content = std::fs::read_to_string(path)?;

        // 간단한 시그니처 파일 형식 파싱 (실제로는 더 복잡한 형식 사용)
        for line in content.lines() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 4 {
                let signature = Signature {
                    name: parts[0].to_string(),
                    hash: parts[1].to_string(),
                    pattern: if parts[2].is_empty() { None } else { Some(parts[2].to_string()) },
                    description: parts[3].to_string(),
                    threat_level: parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(2),
                };

                self.add_signature(signature);
            }
        }

        info!("Signatures loaded successfully from {}", path.display());
        Ok(())
    }

    pub fn get_signature_count(&self) -> (usize, usize) {
        (self.signatures.len(), self.pattern_signatures.len())
    }
}

impl Default for SignatureScanner {
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
    async fn test_eicar_detection() {
        let scanner = SignatureScanner::new();

        // EICAR 테스트 파일 생성
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();

        let analysis = FileAnalysis {
            file_path: temp_file.path().to_path_buf(),
            file_size: 68,
            file_hash: scanner.calculate_eicar_hash(),
            mime_type: "text/plain".to_string(),
            is_executable: false,
            entropy: 0.5,
        };

        let results = scanner.scan_file(temp_file.path(), &analysis).await.unwrap();

        assert!(results.iter().any(|r| r.is_threat && r.signature_name == "EICAR-Test-File"));
    }

    #[test]
    fn test_pattern_matching() {
        let scanner = SignatureScanner::new();

        let content = b"This is a test with powershell -encodedcommand in it";
        assert!(scanner.check_pattern(content, "powershell.*-encodedcommand"));

        let hex_content = &[0x4d, 0x5a, 0x90, 0x00];
        assert!(scanner.check_pattern(hex_content, "hex:4d5a9000"));
    }

    #[test]
    fn test_signature_loading() {
        let scanner = SignatureScanner::new();
        let (hash_count, pattern_count) = scanner.get_signature_count();

        assert!(hash_count > 0);
        assert!(pattern_count > 0);
    }
}