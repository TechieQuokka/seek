# 사용 라이브러리 정리

Seek 백신 CLI에서 활용할 다양한 Rust 라이브러리들을 카테고리별로 정리했습니다.

## 🎯 CLI 프레임워크 & 사용자 인터페이스

### 핵심 CLI 라이브러리
- **[clap](https://crates.io/crates/clap)** - 현대적인 명령행 인수 파서
  - 서브커맨드, 플래그, 도움말 지원
  - derive 매크로로 편리한 API
  - 자동 완성 생성 기능
  ```rust
  clap = { version = "4.4", features = ["derive", "color", "suggestions"] }
  ```

- **[dialoguer](https://crates.io/crates/dialoguer)** - 대화형 CLI 입력
  - 확인 프롬프트, 선택 메뉴, 비밀번호 입력
  - 진행률 바 및 스피너
  ```rust
  dialoguer = "0.11"
  ```

- **[console](https://crates.io/crates/console)** - 터미널 제어
  - 색상, 스타일링, 터미널 크기 감지
  - 크로스 플랫폼 터미널 기능
  ```rust
  console = "0.15"
  ```

### 출력 포맷팅
- **[tabled](https://crates.io/crates/tabled)** - 테이블 포맷팅
  - 다양한 테이블 스타일과 정렬
  - 자동 크기 조정 및 색상 지원
  ```rust
  tabled = "0.14"
  ```

- **[comfy-table](https://crates.io/crates/comfy-table)** - 고급 테이블 생성
  - 복잡한 테이블 레이아웃
  - 동적 열 크기 조정
  ```rust
  comfy-table = "7.1"
  ```

- **[indicatif](https://crates.io/crates/indicatif)** - 진행률 표시
  - 프로그레스 바, 스피너
  - 다중 진행률 표시
  ```rust
  indicatif = "0.17"
  ```

- **[colored](https://crates.io/crates/colored)** - 색상 출력
  - 간단한 색상 및 스타일 적용
  ```rust
  colored = "2.0"
  ```

## ⚡ 비동기 런타임 & 동시성

### 비동기 런타임
- **[tokio](https://crates.io/crates/tokio)** - 비동기 런타임
  - I/O, 네트워킹, 타이머, 작업 스케줄링
  - 멀티스레드 작업 스케줄러
  ```rust
  tokio = { version = "1.35", features = ["full"] }
  ```

- **[async-std](https://crates.io/crates/async-std)** - 대안 비동기 런타임
  - std 라이브러리와 유사한 API
  ```rust
  async-std = { version = "1.12", features = ["attributes"] }
  ```

### 동시성 도구
- **[rayon](https://crates.io/crates/rayon)** - 데이터 병렬 처리
  - 병렬 반복자 및 작업 분할
  - CPU 집약적 작업 최적화
  ```rust
  rayon = "1.8"
  ```

- **[crossbeam](https://crates.io/crates/crossbeam)** - 고성능 동시성
  - 무잠금 데이터 구조
  - 채널 및 스레드 풀
  ```rust
  crossbeam = "0.8"
  ```

- **[parking_lot](https://crates.io/crates/parking_lot)** - 고성능 동기화
  - 빠른 뮤텍스, RwLock
  - std::sync 대체제
  ```rust
  parking_lot = "0.12"
  ```

## 📁 파일 시스템 & I/O

### 파일 시스템 모니터링
- **[notify](https://crates.io/crates/notify)** - 파일 시스템 감시
  - 크로스 플랫폼 파일 변경 감지
  - 이벤트 필터링 및 디바운싱
  ```rust
  notify = "6.1"
  notify-debouncer-mini = "0.4"
  ```

- **[hotwatch](https://crates.io/crates/hotwatch)** - 간단한 파일 감시
  - 고수준 파일 감시 API
  ```rust
  hotwatch = "0.4"
  ```

### 파일 처리
- **[walkdir](https://crates.io/crates/walkdir)** - 디렉토리 순회
  - 재귀적 디렉토리 탐색
  - 심볼릭 링크 처리
  ```rust
  walkdir = "2.4"
  ```

- **[glob](https://crates.io/crates/glob)** - 패턴 매칭
  - 파일 경로 패턴 매칭
  ```rust
  glob = "0.3"
  ```

- **[tempfile](https://crates.io/crates/tempfile)** - 임시 파일 관리
  - 안전한 임시 파일 생성
  ```rust
  tempfile = "3.8"
  ```

- **[memmap2](https://crates.io/crates/memmap2)** - 메모리 매핑
  - 대용량 파일 효율적 처리
  ```rust
  memmap2 = "0.9"
  ```

## 🔐 암호화 & 해시

### 해시 함수
- **[sha2](https://crates.io/crates/sha2)** - SHA-2 해시
  - SHA-256, SHA-512 구현
  ```rust
  sha2 = "0.10"
  ```

- **[md-5](https://crates.io/crates/md-5)** - MD5 해시
  - 레거시 호환성용
  ```rust
  md-5 = "0.10"
  ```

- **[blake3](https://crates.io/crates/blake3)** - BLAKE3 해시
  - 고성능 암호화 해시
  ```rust
  blake3 = "1.5"
  ```

### 암호화
- **[aes-gcm](https://crates.io/crates/aes-gcm)** - AES-GCM 암호화
  - 인증된 암호화
  ```rust
  aes-gcm = "0.10"
  ```

- **[ring](https://crates.io/crates/ring)** - 암호화 라이브러리
  - 다양한 암호화 알고리즘
  ```rust
  ring = "0.17"
  ```

## 🛡️ 백신 & 멀웨어 탐지

### 백신 엔진 바인딩
- **[clamav-rs](https://crates.io/crates/clamav-rs)** - ClamAV 안전한 래퍼
  - libclamav의 안전한 Rust 인터페이스
  - 실시간 스캔 및 시그니처 업데이트
  ```rust
  clamav-rs = "0.3"
  clamav-sys = "0.4"  # 저수준 바인딩
  ```

- **[clamav-client](https://crates.io/crates/clamav-client)** - ClamAV 클라이언트
  - 비동기 ClamAV 데몬 클라이언트
  - Tokio 및 async-std 지원
  ```rust
  clamav-client = "0.3"
  ```

### 위협 정보 & API
- **[virustotal-rs](https://crates.io/crates/virustotal-rs)** - VirusTotal API v3
  - 파일 해시 및 URL 스캔
  - 위협 인텔리전스 조회
  ```rust
  virustotal-rs = "0.3"
  ```

- **[vt3](https://crates.io/crates/vt3)** - VirusTotal REST API v3
  - Public & Enterprise API 지원
  ```rust
  vt3 = "0.9"
  ```

- **[virustotal3](https://crates.io/crates/virustotal3)** - VirusTotal API 라이브러리
  - 멀웨어 스캔 및 분석
  ```rust
  virustotal3 = "0.2"
  ```

### 시그니처 및 패턴 매칭
- **[yara](https://crates.io/crates/yara)** - YARA 룰 엔진
  - 멀웨어 탐지 룰 엔진
  - 사용자 정의 시그니처 지원
  ```rust
  yara = { version = "0.20", optional = true }
  ```

- **[regex](https://crates.io/crates/regex)** - 정규표현식
  - 고성능 정규식 엔진
  - 시그니처 패턴 매칭
  ```rust
  regex = "1.10"
  ```

- **[aho-corasick](https://crates.io/crates/aho-corasick)** - 다중 패턴 검색
  - 빠른 문자열 패턴 매칭
  - 대량 시그니처 동시 검색
  ```rust
  aho-corasick = "1.1"
  ```

### 바이너리 & 악성코드 분석
- **[goblin](https://crates.io/crates/goblin)** - 바이너리 파서
  - ELF, PE, Mach-O 파일 파싱
  - 실행 파일 구조 분석
  ```rust
  goblin = "0.8"
  ```

- **[pelite](https://crates.io/crates/pelite)** - PE 파일 분석
  - Windows PE 파일 상세 분석
  - 임포트/익스포트 테이블 분석
  ```rust
  pelite = "0.10"
  ```

- **[elf](https://crates.io/crates/elf)** - ELF 파일 분석
  - Linux 실행 파일 분석
  ```rust
  elf = "0.7"
  ```

- **[entropy](https://crates.io/crates/entropy)** - 엔트로피 계산
  - 파일 무작위성 분석
  - 패킹 탐지
  ```rust
  entropy = "0.4"
  ```

### 샌드박스 & 격리
- **[jail](https://crates.io/crates/jail)** - 프로세스 격리
  - 안전한 실행 환경
  ```rust
  jail = "0.2"
  ```

- **[nsjail](https://crates.io/crates/nsjail)** - 네임스페이스 격리
  - 리눅스 네임스페이스 활용
  ```rust
  nsjail = "0.1"
  ```

### 보안 검증
- **[check_txt](https://crates.io/crates/check_txt)** - 파일 보안 검사
  - TXT, EPUB 파일 보안 검사
  - VirusTotal 통합
  ```rust
  check_txt = "0.1"
  ```

- **[malwaredb-virustotal](https://crates.io/crates/malwaredb-virustotal)** - 멀웨어 DB 연동
  - VirusTotal과 멀웨어 데이터베이스 통합
  ```rust
  malwaredb-virustotal = "0.1"
  ```

## 🕵️ 보안 유틸리티

## 📊 데이터 처리 & 직렬화

### 직렬화
- **[serde](https://crates.io/crates/serde)** - 직렬화 프레임워크
  - JSON, YAML, TOML 지원
  ```rust
  serde = { version = "1.0", features = ["derive"] }
  serde_json = "1.0"
  serde_yaml = "0.9"
  toml = "0.8"
  ```

- **[bincode](https://crates.io/crates/bincode)** - 바이너리 직렬화
  - 고성능 바이너리 포맷
  ```rust
  bincode = "1.3"
  ```

### 데이터베이스
- **[sqlx](https://crates.io/crates/sqlx)** - 비동기 SQL 드라이버
  - SQLite, PostgreSQL, MySQL 지원
  ```rust
  sqlx = { version = "0.7", features = ["runtime-tokio-rustls", "sqlite"] }
  ```

- **[rusqlite](https://crates.io/crates/rusqlite)** - SQLite 바인딩
  - 동기식 SQLite 인터페이스
  ```rust
  rusqlite = { version = "0.30", features = ["bundled"] }
  ```

- **[sled](https://crates.io/crates/sled)** - 임베디드 데이터베이스
  - 순수 Rust 키-값 저장소
  ```rust
  sled = "0.34"
  ```

## 🕐 시간 & 스케줄링

### 시간 처리
- **[chrono](https://crates.io/crates/chrono)** - 날짜/시간 라이브러리
  - 타임존, 포맷팅, 파싱
  ```rust
  chrono = { version = "0.4", features = ["serde"] }
  ```

- **[time](https://crates.io/crates/time)** - 현대적 시간 라이브러리
  - 안전한 시간 처리
  ```rust
  time = { version = "0.3", features = ["serde"] }
  ```

### 스케줄링
- **[cron](https://crates.io/crates/cron)** - Cron 표현식 파서
  - 스케줄 파싱 및 계산
  ```rust
  cron = "0.12"
  ```

- **[tokio-cron-scheduler](https://crates.io/crates/tokio-cron-scheduler)** - 작업 스케줄러
  - 비동기 크론 작업 실행
  ```rust
  tokio-cron-scheduler = "0.9"
  ```

## 📝 로깅 & 모니터링

### 로깅
- **[tracing](https://crates.io/crates/tracing)** - 구조화된 로깅
  - 비동기 친화적 로깅
  - 스팬 및 이벤트 추적
  ```rust
  tracing = "0.1"
  tracing-subscriber = { version = "0.3", features = ["env-filter"] }
  ```

- **[log](https://crates.io/crates/log)** - 로깅 파사드
  - 표준 로깅 인터페이스
  ```rust
  log = "0.4"
  env_logger = "0.10"
  ```

- **[slog](https://crates.io/crates/slog)** - 구조화된 로깅
  - 성능 중심 로깅
  ```rust
  slog = "2.7"
  ```

### 메트릭 및 모니터링
- **[metrics](https://crates.io/crates/metrics)** - 메트릭 수집
  - 카운터, 게이지, 히스토그램
  ```rust
  metrics = "0.22"
  ```

- **[prometheus](https://crates.io/crates/prometheus)** - Prometheus 메트릭
  - 모니터링 메트릭 내보내기
  ```rust
  prometheus = "0.13"
  ```

## 🌐 네트워킹 & HTTP

### HTTP 클라이언트
- **[reqwest](https://crates.io/crates/reqwest)** - HTTP 클라이언트
  - 비동기 HTTP 요청
  - JSON 지원
  ```rust
  reqwest = { version = "0.11", features = ["json"] }
  ```

- **[ureq](https://crates.io/crates/ureq)** - 경량 HTTP 클라이언트
  - 동기식 HTTP 클라이언트
  ```rust
  ureq = "2.9"
  ```

### 네트워킹
- **[tokio-tungstenite](https://crates.io/crates/tokio-tungstenite)** - WebSocket
  - 비동기 WebSocket 구현
  ```rust
  tokio-tungstenite = "0.21"
  ```

## 🧪 테스트 & 개발 도구

### 테스트
- **[criterion](https://crates.io/crates/criterion)** - 벤치마킹
  - 통계적 성능 측정
  ```rust
  [dev-dependencies]
  criterion = "0.5"
  ```

- **[mockall](https://crates.io/crates/mockall)** - 모킹 프레임워크
  - 자동 mock 생성
  ```rust
  mockall = "0.12"
  ```

- **[proptest](https://crates.io/crates/proptest)** - 속성 기반 테스트
  - 퍼즈 테스트
  ```rust
  proptest = "1.4"
  ```

### 개발 지원
- **[assert_cmd](https://crates.io/crates/assert_cmd)** - CLI 테스트
  - 명령행 응용프로그램 테스트
  ```rust
  assert_cmd = "2.0"
  ```

- **[predicates](https://crates.io/crates/predicates)** - 테스트 어설션
  - 복잡한 조건 검사
  ```rust
  predicates = "3.0"
  ```

## 🔧 유틸리티 & 도우미

### 에러 처리
- **[anyhow](https://crates.io/crates/anyhow)** - 에러 처리
  - 간편한 에러 전파
  ```rust
  anyhow = "1.0"
  ```

- **[thiserror](https://crates.io/crates/thiserror)** - 에러 타입 정의
  - 사용자 정의 에러 타입
  ```rust
  thiserror = "1.0"
  ```

- **[eyre](https://crates.io/crates/eyre)** - 향상된 에러 리포팅
  - 상세한 에러 컨텍스트
  ```rust
  eyre = "0.6"
  ```

### 설정 관리
- **[config](https://crates.io/crates/config)** - 설정 관리
  - 다중 소스 설정 로딩
  ```rust
  config = "0.14"
  ```

- **[clap-serde](https://crates.io/crates/clap-serde)** - CLI 설정 통합
  - clap과 serde 통합
  ```rust
  clap-serde = "0.2"
  ```

### 압축
- **[flate2](https://crates.io/crates/flate2)** - 압축/해제
  - GZIP, DEFLATE 지원
  ```rust
  flate2 = "1.0"
  ```

- **[zip](https://crates.io/crates/zip)** - ZIP 아카이브
  - ZIP 파일 생성/추출
  ```rust
  zip = "0.6"
  ```

- **[tar](https://crates.io/crates/tar)** - TAR 아카이브
  - TAR 파일 처리
  ```rust
  tar = "0.4"
  ```

## 🚀 성능 최적화

### 메모리 관리
- **[mimalloc](https://crates.io/crates/mimalloc)** - 고성능 할당자
  - 빠른 메모리 할당
  ```rust
  mimalloc = "0.1"
  ```

- **[jemallocator](https://crates.io/crates/jemallocator)** - jemalloc 할당자
  - 메모리 사용량 최적화
  ```rust
  jemallocator = "0.5"
  ```

### 프로파일링
- **[pprof](https://crates.io/crates/pprof)** - 성능 프로파일링
  - CPU 및 메모리 프로파일링
  ```rust
  pprof = { version = "0.13", features = ["flamegraph"] }
  ```

## 🛠️ 플랫폼별 기능

### Windows
- **[winapi](https://crates.io/crates/winapi)** - Windows API
  - 네이티브 Windows 기능
  ```rust
  [target.'cfg(windows)'.dependencies]
  winapi = { version = "0.3", features = ["winuser", "processthreadsapi"] }
  ```

- **[windows](https://crates.io/crates/windows)** - 현대적 Windows API
  - 타입 안전한 Windows API
  ```rust
  windows = "0.52"
  ```

### Unix/Linux
- **[nix](https://crates.io/crates/nix)** - Unix 시스템 콜
  - 저수준 Unix 기능
  ```rust
  [target.'cfg(unix)'.dependencies]
  nix = "0.27"
  ```

## 💾 Cargo.toml 예시

```toml
[package]
name = "seek"
version = "0.1.0"
edition = "2021"

[dependencies]
# CLI Framework
clap = { version = "4.4", features = ["derive", "color", "suggestions"] }
dialoguer = "0.11"
console = "0.15"

# Async Runtime
tokio = { version = "1.35", features = ["full"] }
rayon = "1.8"

# File System
notify = "6.1"
notify-debouncer-mini = "0.4"
walkdir = "2.4"
glob = "0.3"

# Antivirus & Security
clamav-rs = "0.3"
clamav-sys = "0.4"
clamav-client = "0.3"
virustotal-rs = "0.3"
vt3 = "0.9"
yara = { version = "0.20", optional = true }

# Security & Crypto
sha2 = "0.10"
md-5 = "0.10"
blake3 = "1.5"
regex = "1.10"

# Data & Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"
sqlx = { version = "0.7", features = ["runtime-tokio-rustls", "sqlite"] }

# Time & Scheduling
chrono = { version = "0.4", features = ["serde"] }
tokio-cron-scheduler = "0.9"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# UI & Output
tabled = "0.14"
indicatif = "0.17"
colored = "2.0"

# Error Handling
anyhow = "1.0"
thiserror = "1.0"

# Networking
reqwest = { version = "0.11", features = ["json"] }

# Binary Analysis
goblin = "0.8"

[dev-dependencies]
criterion = "0.5"
mockall = "0.12"
proptest = "1.4"
assert_cmd = "2.0"
predicates = "3.0"
tempfile = "3.8"

[features]
default = ["yara-support"]
yara-support = ["yara"]
full-crypto = ["ring", "aes-gcm"]
```

이 라이브러리 목록을 통해 강력하고 다양한 기능을 갖춘 백신 CLI를 구축할 수 있습니다.