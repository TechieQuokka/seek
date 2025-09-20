use crate::engine::filesystem::file_analyzer::FileAnalysis;
use crate::error::Result;
use std::path::Path;
use tracing::debug;

#[derive(Debug, Clone)]
pub struct HeuristicResult {
    pub rule_name: String,
    pub is_suspicious: bool,
    pub confidence: f32,
    pub description: String,
    pub risk_score: u8,
}

pub struct HeuristicScanner {
    entropy_threshold: f64,
    size_thresholds: (u64, u64), // (min, max) suspicious sizes
}

impl HeuristicScanner {
    pub fn new() -> Self {
        Self {
            entropy_threshold: 7.5, // 높은 엔트로피는 암호화/패킹 의심
            size_thresholds: (0, 1024), // 너무 작거나 빈 파일
        }
    }

    pub async fn scan_file(
        &self,
        file_path: &Path,
        analysis: &FileAnalysis,
    ) -> Result<Vec<HeuristicResult>> {
        debug!("Running heuristic scan for: {}", file_path.display());

        let mut results = Vec::new();

        // 1. 파일명 기반 휴리스틱
        results.extend(self.check_filename_heuristics(file_path));

        // 2. 파일 크기 기반 휴리스틱
        results.extend(self.check_size_heuristics(analysis));

        // 3. 엔트로피 기반 휴리스틱
        results.extend(self.check_entropy_heuristics(analysis));

        // 4. 확장자 기반 휴리스틱
        results.extend(self.check_extension_heuristics(file_path, analysis));

        // 5. 내용 기반 휴리스틱
        if let Ok(content) = std::fs::read(file_path) {
            results.extend(self.check_content_heuristics(file_path, &content));
        }

        // 안전한 파일인 경우
        if results.is_empty() || results.iter().all(|r| !r.is_suspicious) {
            results.push(HeuristicResult {
                rule_name: "Clean-File".to_string(),
                is_suspicious: false,
                confidence: 0.9,
                description: "No suspicious behavior detected".to_string(),
                risk_score: 0,
            });
        }

        Ok(results)
    }

    fn check_filename_heuristics(&self, file_path: &Path) -> Vec<HeuristicResult> {
        let mut results = Vec::new();

        if let Some(filename) = file_path.file_name().and_then(|n| n.to_str()) {
            let lower_filename = filename.to_lowercase();

            // 이중 확장자 검사
            if filename.matches('.').count() >= 2 &&
                (lower_filename.ends_with(".exe") || lower_filename.ends_with(".scr") ||
                    lower_filename.ends_with(".bat") || lower_filename.ends_with(".cmd") ||
                    lower_filename.ends_with(".pif")) {
                results.push(HeuristicResult {
                    rule_name: "Double-Extension".to_string(),
                    is_suspicious: true,
                    confidence: 0.9,
                    description: "File has suspicious double extension".to_string(),
                    risk_score: 8,
                });
            }

            // 시스템 파일 위장
            let system_files = ["svchost.exe", "explorer.exe", "winlogon.exe", "csrss.exe"];
            if system_files.iter().any(|&sf| lower_filename == sf)
                && !file_path.to_string_lossy().to_lowercase().contains("system32") &&
                   !file_path.to_string_lossy().to_lowercase().contains("syswow64") {
                results.push(HeuristicResult {
                    rule_name: "System-File-Impersonation".to_string(),
                    is_suspicious: true,
                    confidence: 0.8,
                    description: "File impersonating system executable in wrong location".to_string(),
                    risk_score: 9,
                });
            }

            // 의심스러운 파일명 패턴
            let suspicious_patterns = [
                "fake", "crack", "keygen", "patch", "hack", "trojan", "virus",
                "malware", "ransom", "backdoor", "rootkit"
            ];

            for pattern in &suspicious_patterns {
                if lower_filename.contains(pattern) {
                    results.push(HeuristicResult {
                        rule_name: "Suspicious-Filename".to_string(),
                        is_suspicious: true,
                        confidence: 0.7,
                        description: format!("Filename contains suspicious keyword: {}", pattern),
                        risk_score: 6,
                    });
                    break;
                }
            }

            // 랜덤한 파일명 패턴 (길이가 길고 무작위 문자)
            if filename.len() > 20 && filename.chars().filter(|c| c.is_alphanumeric()).count() > 15 {
                let alpha_ratio = filename.chars().filter(|c| c.is_alphabetic()).count() as f32 / filename.len() as f32;
                if !(0.3..=0.9).contains(&alpha_ratio) {
                    results.push(HeuristicResult {
                        rule_name: "Random-Filename".to_string(),
                        is_suspicious: true,
                        confidence: 0.6,
                        description: "Filename appears to be randomly generated".to_string(),
                        risk_score: 5,
                    });
                }
            }
        }

        results
    }

    fn check_size_heuristics(&self, analysis: &FileAnalysis) -> Vec<HeuristicResult> {
        let mut results = Vec::new();

        // 빈 파일 또는 너무 작은 실행 파일
        if analysis.file_size == 0 {
            results.push(HeuristicResult {
                rule_name: "Empty-File".to_string(),
                is_suspicious: true,
                confidence: 0.8,
                description: "File is empty".to_string(),
                risk_score: 7,
            });
        } else if analysis.is_executable && analysis.file_size < 1024 {
            results.push(HeuristicResult {
                rule_name: "Tiny-Executable".to_string(),
                is_suspicious: true,
                confidence: 0.7,
                description: "Executable file is suspiciously small".to_string(),
                risk_score: 6,
            });
        }

        // 비정상적으로 큰 스크립트 파일
        if analysis.file_path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| {
            matches!(ext.to_lowercase().as_str(), "ps1" | "vbs" | "js" | "bat" | "cmd")
        }) && analysis.file_size > 100_000 {
            results.push(HeuristicResult {
                rule_name: "Large-Script".to_string(),
                is_suspicious: true,
                confidence: 0.6,
                description: "Script file is unusually large".to_string(),
                risk_score: 5,
            });
        }

        results
    }

    fn check_entropy_heuristics(&self, analysis: &FileAnalysis) -> Vec<HeuristicResult> {
        let mut results = Vec::new();

        // 높은 엔트로피 = 암호화/패킹된 파일 의심
        if analysis.entropy > self.entropy_threshold {
            results.push(HeuristicResult {
                rule_name: "High-Entropy".to_string(),
                is_suspicious: true,
                confidence: 0.7,
                description: format!("File has high entropy ({:.2}), possibly packed or encrypted", analysis.entropy),
                risk_score: 6,
            });
        }

        // 실행 파일인데 엔트로피가 너무 낮음 (의심스러운 패턴)
        if analysis.is_executable && analysis.entropy < 1.0 {
            results.push(HeuristicResult {
                rule_name: "Low-Entropy-Executable".to_string(),
                is_suspicious: true,
                confidence: 0.6,
                description: "Executable has unusually low entropy".to_string(),
                risk_score: 4,
            });
        }

        results
    }

    fn check_extension_heuristics(&self, file_path: &Path, analysis: &FileAnalysis) -> Vec<HeuristicResult> {
        let mut results = Vec::new();

        if let Some(extension) = file_path.extension().and_then(|ext| ext.to_str()) {
            let lower_ext = extension.to_lowercase();

            // 위험한 확장자
            let dangerous_extensions = [
                "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "js", "jar",
                "wsf", "wsh", "ps1", "reg", "msi"
            ];

            if dangerous_extensions.contains(&lower_ext.as_str()) {
                results.push(HeuristicResult {
                    rule_name: "Dangerous-Extension".to_string(),
                    is_suspicious: true,
                    confidence: 0.8,
                    description: format!("File has potentially dangerous extension: .{}", lower_ext),
                    risk_score: 7,
                });
            }

            // MIME 타입과 확장자 불일치
            let expected_mime = mime_guess::from_ext(&lower_ext).first_or_octet_stream();
            if expected_mime.to_string() != analysis.mime_type {
                results.push(HeuristicResult {
                    rule_name: "MIME-Extension-Mismatch".to_string(),
                    is_suspicious: true,
                    confidence: 0.6,
                    description: "File extension doesn't match MIME type".to_string(),
                    risk_score: 5,
                });
            }
        }

        results
    }

    fn check_content_heuristics(&self, file_path: &Path, content: &[u8]) -> Vec<HeuristicResult> {
        let mut results = Vec::new();

        // 크기 제한 (큰 파일은 스킵)
        if content.len() > 10_485_760 { // 10MB
            return results;
        }

        // 문자열로 변환 가능한 경우 추가 검사
        if let Ok(content_str) = std::str::from_utf8(content) {
            let lower_content = content_str.to_lowercase();

            // 의심스러운 키워드 검사
            let suspicious_keywords = [
                ("ransom", "Ransomware-Keywords", 9),
                ("decrypt", "Decryption-Keywords", 8),
                ("bitcoin", "Cryptocurrency-Keywords", 7),
                ("trojan", "Trojan-Keywords", 8),
                ("backdoor", "Backdoor-Keywords", 9),
                ("keylogger", "Keylogger-Keywords", 8),
                ("rootkit", "Rootkit-Keywords", 9),
                ("botnet", "Botnet-Keywords", 8),
            ];

            for (keyword, rule_name, risk_score) in &suspicious_keywords {
                if lower_content.contains(keyword) {
                    results.push(HeuristicResult {
                        rule_name: rule_name.to_string(),
                        is_suspicious: true,
                        confidence: 0.7,
                        description: format!("Content contains suspicious keyword: {}", keyword),
                        risk_score: *risk_score,
                    });
                }
            }

            // PowerShell 의심 명령어
            let powershell_patterns = [
                "invoke-expression", "iex", "downloadstring", "encodedcommand",
                "bypass", "unrestricted", "hidden", "windowstyle"
            ];

            for pattern in &powershell_patterns {
                if lower_content.contains(pattern) {
                    results.push(HeuristicResult {
                        rule_name: "Suspicious-PowerShell".to_string(),
                        is_suspicious: true,
                        confidence: 0.8,
                        description: format!("Contains suspicious PowerShell pattern: {}", pattern),
                        risk_score: 8,
                    });
                    break;
                }
            }

            // VBScript 의심 명령어
            let vbs_patterns = [
                "wscript.shell", "createobject", "shell.application",
                "downloadfile", "savetofile"
            ];

            for pattern in &vbs_patterns {
                if lower_content.contains(pattern) {
                    results.push(HeuristicResult {
                        rule_name: "Suspicious-VBScript".to_string(),
                        is_suspicious: true,
                        confidence: 0.8,
                        description: format!("Contains suspicious VBScript pattern: {}", pattern),
                        risk_score: 8,
                    });
                    break;
                }
            }

            // Base64 인코딩된 내용 (대량)
            let base64_chars = content_str.chars().filter(|c| {
                c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '='
            }).count();

            if base64_chars > content_str.len() * 8 / 10 && content_str.len() > 100 {
                results.push(HeuristicResult {
                    rule_name: "Base64-Encoded-Content".to_string(),
                    is_suspicious: true,
                    confidence: 0.6,
                    description: "Content appears to be heavily Base64 encoded".to_string(),
                    risk_score: 6,
                });
            }
        }

        // PE 헤더 검사
        if content.len() >= 64 && content[0] == 0x4D && content[1] == 0x5A { // MZ header
            // DOS 헤더에서 PE 헤더 오프셋 읽기
            if let Some(pe_offset) = content.get(60..64) {
                let pe_offset = u32::from_le_bytes([pe_offset[0], pe_offset[1], pe_offset[2], pe_offset[3]]) as usize;

                if pe_offset < content.len().saturating_sub(4) {
                    if let Some(pe_signature) = content.get(pe_offset..pe_offset + 4) {
                        if pe_signature == b"PE\0\0" {
                            // 확장자가 PE 파일이 아닌데 PE 헤더가 있는 경우
                            if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                                if !matches!(ext.to_lowercase().as_str(), "exe" | "dll" | "sys" | "scr") {
                                    results.push(HeuristicResult {
                                        rule_name: "Hidden-PE-File".to_string(),
                                        is_suspicious: true,
                                        confidence: 0.9,
                                        description: "File contains PE header but has non-executable extension".to_string(),
                                        risk_score: 9,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        results
    }

    pub fn set_entropy_threshold(&mut self, threshold: f64) {
        self.entropy_threshold = threshold;
    }

    pub fn set_size_thresholds(&mut self, min: u64, max: u64) {
        self.size_thresholds = (min, max);
    }
}

impl Default for HeuristicScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[tokio::test]
    async fn test_double_extension_detection() {
        let scanner = HeuristicScanner::new();
        let file_path = PathBuf::from("document.pdf.exe");

        let analysis = FileAnalysis {
            file_path: file_path.clone(),
            file_size: 1000,
            file_hash: "test_hash".to_string(),
            mime_type: "application/octet-stream".to_string(),
            is_executable: true,
            entropy: 5.0,
        };

        let results = scanner.scan_file(&file_path, &analysis).await.unwrap();

        assert!(results.iter().any(|r| r.is_suspicious && r.rule_name == "Double-Extension"));
    }

    #[tokio::test]
    async fn test_suspicious_content_detection() {
        let scanner = HeuristicScanner::new();

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"This file contains ransom payment instructions with bitcoin address").unwrap();

        let analysis = FileAnalysis {
            file_path: temp_file.path().to_path_buf(),
            file_size: temp_file.as_file().metadata().unwrap().len(),
            file_hash: "test_hash".to_string(),
            mime_type: "text/plain".to_string(),
            is_executable: false,
            entropy: 4.0,
        };

        let results = scanner.scan_file(temp_file.path(), &analysis).await.unwrap();

        assert!(results.iter().any(|r| r.is_suspicious && r.rule_name.contains("Ransomware")));
    }

    #[test]
    fn test_entropy_threshold() {
        let mut scanner = HeuristicScanner::new();
        scanner.set_entropy_threshold(6.0);

        let analysis = FileAnalysis {
            file_path: PathBuf::from("test.exe"),
            file_size: 1000,
            file_hash: "test_hash".to_string(),
            mime_type: "application/octet-stream".to_string(),
            is_executable: true,
            entropy: 7.0,
        };

        let results = scanner.check_entropy_heuristics(&analysis);
        assert!(results.iter().any(|r| r.rule_name == "High-Entropy"));
    }
}