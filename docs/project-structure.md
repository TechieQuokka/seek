# 프로젝트 구조

## 디렉토리 구조

```
seek/
├── Cargo.toml                    # 프로젝트 설정 및 의존성
├── Cargo.lock                    # 의존성 잠금 파일
├── README.md                     # 프로젝트 개요
├── LICENSE                       # 라이선스 파일
├── .gitignore                    # Git 무시 파일
├── .github/                      # GitHub 워크플로우
│   └── workflows/
│       ├── ci.yml               # 지속적 통합
│       ├── release.yml          # 릴리스 자동화
│       └── security.yml         # 보안 검사
├── src/                         # 소스 코드
│   ├── main.rs                  # 엔트리 포인트
│   ├── lib.rs                   # 라이브러리 루트
│   ├── cli/                     # CLI 인터페이스
│   │   ├── mod.rs
│   │   ├── args.rs              # 명령행 인수 정의
│   │   ├── output.rs            # 출력 포맷팅
│   │   └── commands/            # 명령어 핸들러
│   │       ├── mod.rs
│   │       ├── scan.rs          # 스캔 명령어
│   │       ├── monitor.rs       # 모니터링 명령어
│   │       ├── quarantine.rs    # 격리 명령어
│   │       ├── update.rs        # 업데이트 명령어
│   │       ├── schedule.rs      # 스케줄 명령어
│   │       ├── config.rs        # 설정 명령어
│   │       ├── report.rs        # 리포트 명령어
│   │       └── status.rs        # 상태 명령어
│   ├── services/                # 서비스 레이어
│   │   ├── mod.rs
│   │   ├── scanner_service.rs   # 스캔 서비스
│   │   ├── monitor_service.rs   # 모니터링 서비스
│   │   ├── scheduler_service.rs # 스케줄러 서비스
│   │   └── quarantine_service.rs # 격리 서비스
│   ├── engine/                  # 핵심 엔진
│   │   ├── mod.rs
│   │   ├── detection/           # 탐지 엔진
│   │   │   ├── mod.rs
│   │   │   ├── signature_scanner.rs
│   │   │   ├── heuristic_scanner.rs
│   │   │   └── yara_scanner.rs
│   │   ├── filesystem/          # 파일시스템 엔진
│   │   │   ├── mod.rs
│   │   │   ├── file_watcher.rs
│   │   │   ├── file_analyzer.rs
│   │   │   └── path_handler.rs
│   │   └── signature/           # 시그니처 엔진
│   │       ├── mod.rs
│   │       ├── signature_db.rs
│   │       ├── signature_updater.rs
│   │       └── hash_engine.rs
│   ├── data/                    # 데이터 레이어
│   │   ├── mod.rs
│   │   ├── config/              # 설정 관리
│   │   │   ├── mod.rs
│   │   │   ├── app_config.rs
│   │   │   └── scan_config.rs
│   │   ├── storage/             # 저장소 관리
│   │   │   ├── mod.rs
│   │   │   ├── quarantine_store.rs
│   │   │   ├── log_store.rs
│   │   │   └── report_store.rs
│   │   └── models/              # 데이터 모델
│   │       ├── mod.rs
│   │       ├── threat.rs
│   │       ├── scan_result.rs
│   │       └── config.rs
│   ├── utils/                   # 유틸리티
│   │   ├── mod.rs
│   │   ├── crypto.rs            # 암호화 유틸
│   │   ├── compression.rs       # 압축 유틸
│   │   ├── network.rs           # 네트워크 유틸
│   │   └── platform.rs          # 플랫폼별 유틸
│   └── error.rs                 # 에러 타입 정의
├── tests/                       # 통합 테스트
│   ├── integration/
│   │   ├── cli_tests.rs         # CLI 테스트
│   │   ├── scan_tests.rs        # 스캔 테스트
│   │   └── monitor_tests.rs     # 모니터링 테스트
│   └── fixtures/                # 테스트 데이터
│       ├── clean_files/
│       ├── infected_files/
│       └── config_samples/
├── benches/                     # 벤치마크
│   ├── scan_benchmark.rs        # 스캔 성능 벤치마크
│   └── detection_benchmark.rs   # 탐지 성능 벤치마크
├── docs/                        # 문서
│   ├── architecture.md          # 아키텍처 설계
│   ├── components.md            # 컴포넌트 설계
│   ├── cli-interface.md         # CLI 인터페이스
│   ├── project-structure.md     # 프로젝트 구조 (이 파일)
│   ├── development.md           # 개발 가이드
│   ├── deployment.md            # 배포 가이드
│   └── api/                     # API 문서
│       └── README.md
├── config/                      # 설정 파일
│   ├── default.toml             # 기본 설정
│   ├── development.toml         # 개발 환경 설정
│   └── production.toml          # 프로덕션 환경 설정
├── scripts/                     # 스크립트
│   ├── build.sh                 # 빌드 스크립트
│   ├── test.sh                  # 테스트 스크립트
│   ├── benchmark.sh             # 벤치마크 스크립트
│   └── release.sh               # 릴리스 스크립트
└── assets/                      # 정적 자산
    ├── signatures/              # 기본 시그니처
    ├── rules/                   # YARA 룰
    └── icons/                   # 아이콘 파일
```

## 핵심 파일 설명

### Cargo.toml
```toml
[package]
name = "seek"
version = "0.1.0"
edition = "2021"
authors = ["Your Name <email@example.com>"]
description = "고성능 Rust 백신 CLI 도구"
license = "MIT"
repository = "https://github.com/username/seek"
readme = "README.md"
keywords = ["antivirus", "security", "malware", "cli"]
categories = ["command-line-utilities", "security"]

[dependencies]
# CLI 프레임워크
clap = { version = "4.0", features = ["derive", "color"] }

# 비동기 런타임
tokio = { version = "1.0", features = ["full"] }

# 파일 시스템 감시
notify = "6.0"

# 암호화 및 해시
sha2 = "0.10"
md5 = "0.7"

# 직렬화
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"

# 로깅
log = "0.4"
env_logger = "0.10"

# 시간 처리
chrono = { version = "0.4", features = ["serde"] }

# 파일 순회
walkdir = "2.3"

# 정규표현식
regex = "1.7"

# YARA 바인딩 (선택사항)
yara = { version = "0.20", optional = true }

# 에러 처리
anyhow = "1.0"
thiserror = "1.0"

# 진행률 표시
indicatif = "0.17"

# 색상 출력
colored = "2.0"

# 테이블 포맷팅
tabled = "0.14"

[dev-dependencies]
# 테스트 프레임워크
criterion = "0.5"
tempfile = "3.8"
assert_cmd = "2.0"
predicates = "3.0"

[features]
default = ["yara-support"]
yara-support = ["yara"]
```

### main.rs
```rust
use clap::Parser;
use seek::{cli, config, error::Result};

#[tokio::main]
async fn main() -> Result<()> {
    // 로깅 초기화
    env_logger::init();

    // 설정 로드
    let config = config::load_config()?;

    // CLI 파싱 및 실행
    let args = cli::Args::parse();
    cli::run(args, config).await
}
```

### lib.rs
```rust
pub mod cli;
pub mod services;
pub mod engine;
pub mod data;
pub mod utils;
pub mod error;

pub use error::{Error, Result};
```

## 모듈 의존성

```
CLI Layer
    ↓
Service Layer
    ↓
Engine Layer
    ↓
Data Layer
```

### 의존성 규칙
1. **상위 레이어는 하위 레이어에만 의존**
2. **같은 레이어 내에서는 순환 의존성 금지**
3. **인터페이스(trait)를 통한 느슨한 결합**
4. **의존성 주입 패턴 활용**

## 빌드 및 테스트

### 빌드 명령어
```bash
# 개발 빌드
cargo build

# 릴리스 빌드
cargo build --release

# 특정 기능으로 빌드
cargo build --features yara-support

# 크로스 컴파일 (Windows용)
cargo build --target x86_64-pc-windows-gnu
```

### 테스트 명령어
```bash
# 단위 테스트
cargo test

# 통합 테스트
cargo test --test integration

# 벤치마크
cargo bench

# 코드 커버리지
cargo tarpaulin --out Html
```

### 문서 생성
```bash
# API 문서 생성
cargo doc --open

# README 업데이트
cargo readme > README.md
```

## 배포 구조

### 바이너리 배포
```
seek-v0.1.0-x86_64-linux/
├── seek                    # 실행 파일
├── config/
│   └── default.toml       # 기본 설정
├── signatures/            # 시그니처 파일
├── LICENSE
└── README.md
```

### 패키지 관리자 배포
- **Cargo**: `cargo install seek`
- **Homebrew**: `brew install seek`
- **APT**: `apt install seek`
- **Chocolatey**: `choco install seek`

## 개발 워크플로우

### 브랜치 전략
```
main                 # 안정 버전
├── develop          # 개발 브랜치
├── feature/xxx      # 기능 개발
├── bugfix/xxx       # 버그 수정
└── release/x.x.x    # 릴리스 준비
```

### 코드 품질 도구
- **Rustfmt**: 코드 포맷팅
- **Clippy**: 린팅
- **Cargo audit**: 보안 취약점 검사
- **Tarpaulin**: 코드 커버리지

### CI/CD 파이프라인
1. **코드 품질 검사**
2. **단위 테스트 실행**
3. **통합 테스트 실행**
4. **보안 검사**
5. **벤치마크 실행**
6. **빌드 및 패키징**
7. **배포**