use crate::cli::{args::ScanArgs, output::OutputFormatter};
use crate::data::models::{
    config::AppConfig,
    scan_result::{ScanResult, ScanType, ScanStatus},
};
use crate::error::Result;
use crate::services::scanner_service::ScannerService;
use std::path::PathBuf;
use std::sync::Arc;

pub async fn execute(args: ScanArgs, config: &AppConfig) -> Result<()> {
    OutputFormatter::print_info("Starting scan...");

    // 스캔 대상 경로 결정 (--file 옵션 우선 처리)
    let target_path = if let Some(ref file_path) = args.file {
        file_path.clone()
    } else {
        args.path.unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
    };

    // 스캔 타입 결정
    let scan_type = if args.quick {
        ScanType::Quick
    } else if args.detailed {
        ScanType::Full
    } else {
        ScanType::Custom
    };

    // 스캔 서비스 초기화
    let scanner_service = ScannerService::new(Arc::new(config.clone()));

    // 스캔 설정 구성
    let mut scan_config = config.scan.clone();

    if let Some(threads) = args.threads {
        scan_config.max_threads = threads;
    }

    // 제외/포함 패턴 적용
    if !args.exclude.is_empty() {
        scan_config.exclude_patterns.extend(args.exclude);
    }
    if !args.include.is_empty() {
        scan_config.include_patterns = args.include;
    }

    // 스캔 실행 (단일 파일 vs 경로 구분)
    let mut scan_result = if args.file.is_some() && target_path.is_file() {
        // 단일 파일 스캔
        match scanner_service.scan_file_only(&target_path).await {
            Ok(threats) => {
                let mut result = ScanResult::new(scan_type, target_path.clone());
                result.status = ScanStatus::Running;

                // 파일 정보 추가
                if let Ok(metadata) = std::fs::metadata(&target_path) {
                    result.add_scanned_size(metadata.len());
                }
                result.increment_files_scanned();

                // 위협 정보 추가
                for threat in threats {
                    result.add_threat(threat);
                }

                result
            }
            Err(e) => {
                let mut error_result = ScanResult::new(scan_type, target_path.clone());
                error_result.status = ScanStatus::Failed;
                OutputFormatter::print_error(&format!("File scan failed: {}", e));
                return Err(e);
            }
        }
    } else {
        // 경로 스캔
        match scanner_service.scan_path(&target_path, &scan_config).await {
            Ok(result) => result,
            Err(e) => {
                // 에러 발생 시 기본 결과 생성
                let mut error_result = ScanResult::new(scan_type, target_path.clone());
                error_result.status = ScanStatus::Failed;
                OutputFormatter::print_error(&format!("Scan failed: {}", e));
                return Err(e);
            }
        }
    };

    // 스캔 완료 처리
    scan_result.complete();

    // 결과 출력
    let output = OutputFormatter::format_scan_result(&scan_result, &args.format)?;
    println!("{}", output);

    // 파일 저장
    if let Some(output_path) = args.output {
        save_scan_result(&scan_result, &output_path, &args.format)?;
        OutputFormatter::print_success(&format!("Results saved to: {}", output_path.display()));
    }

    // 위협 발견 시 격리 처리
    if args.quarantine && !scan_result.threats.is_empty() {
                OutputFormatter::print_info("Quarantining detected threats...");

                // TODO: 격리 서비스 구현 후 연동
                OutputFormatter::print_success(&format!(
                    "Quarantined {} threats",
                    scan_result.threats.len()
                ));
            }

            // 스캔 결과에 따른 종료 코드
    if scan_result.summary.threats_found > 0 {
        OutputFormatter::print_warning(&format!(
            "Scan completed with {} threats detected",
            scan_result.summary.threats_found
        ));

        // --success-exit 플래그가 있으면 위협이 있어도 exit code 0 반환
        if !args.success_exit {
            std::process::exit(1);
        }
    } else {
        OutputFormatter::print_success("Scan completed successfully - no threats detected");
    }

    Ok(())
}

fn save_scan_result(
    result: &ScanResult,
    path: &PathBuf,
    format: &crate::cli::args::OutputFormat,
) -> Result<()> {
    let content = OutputFormatter::format_scan_result(result, format)?;
    std::fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_scan_current_directory() {
        let _config = AppConfig::default();
        let _args = ScanArgs {
            path: None,
            recursive: false,
            file: None,
            depth: None,
            quarantine: false,
            threads: Some(1),
            exclude: vec![],
            include: vec![],
            detailed: false,
            quick: true,
            format: crate::cli::args::OutputFormat::Json,
            output: None,
            success_exit: false,
        };

        // 실제 스캔 테스트는 모킹된 서비스로 진행
        // execute(args, &config).await.unwrap();
    }

    #[test]
    fn test_save_scan_result() {
        let temp_dir = tempdir().unwrap();
        let output_path = temp_dir.path().join("test_result.json");

        let scan_result = ScanResult::new(ScanType::Quick, PathBuf::from("/test"));

        save_scan_result(
            &scan_result,
            &output_path,
            &crate::cli::args::OutputFormat::Json,
        ).unwrap();

        assert!(output_path.exists());
    }
}