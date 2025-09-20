# 모듈별 컴포넌트 설계

## CLI Interface Layer

### 구조
```rust
// src/cli/mod.rs
pub mod commands;
pub mod args;
pub mod output;
```

### 주요 역할
- 사용자 입력 파싱과 검증
- 명령어 라우팅
- 결과 출력 및 포맷팅
- 사용자 인터랙션 처리

### 세부 모듈

#### Commands Module
각 주요 기능별 명령어 처리기
```rust
// src/cli/commands/
├── mod.rs
├── scan.rs          // 스캔 명령어 처리
├── monitor.rs       // 모니터링 명령어 처리
├── quarantine.rs    // 격리 명령어 처리
├── update.rs        // 업데이트 명령어 처리
└── schedule.rs      // 스케줄 명령어 처리
```

## Service Layer

### 구조
```rust
// src/services/
├── scanner_service.rs     // 스캔 로직 조율
├── monitor_service.rs     // 실시간 모니터링
├── scheduler_service.rs   // 스케줄 관리
└── quarantine_service.rs  // 격리 관리
```

### Scanner Service
- 스캔 작업 조율 및 관리
- 여러 탐지 엔진 통합
- 스캔 결과 수집 및 처리
- 성능 모니터링

### Monitor Service
- 파일 시스템 실시간 감시
- 변경 이벤트 처리
- 백그라운드 스캔 실행
- 알림 및 로깅

### Scheduler Service
- 정기 스캔 스케줄 관리
- 크론 표현식 처리
- 작업 큐 관리
- 스케줄 지속성

### Quarantine Service
- 감염 파일 격리
- 격리 파일 관리
- 복구 및 삭제 기능
- 격리 정책 적용

## Core Engine Layer

### Detection Engine
```rust
// src/engine/detection/
├── signature_scanner.rs  // 시그니처 기반 스캔
├── heuristic_scanner.rs  // 휴리스틱 분석
└── yara_scanner.rs       // YARA 룰 엔진
```

#### Signature Scanner
- 알려진 시그니처 매칭
- MD5/SHA256 해시 비교
- 바이트 패턴 검색
- 빠른 스캔 최적화

#### Heuristic Scanner
- 의심스러운 행동 패턴 분석
- 엔트로피 분석
- 실행 파일 구조 검사
- 위험도 점수 계산

#### YARA Scanner
- YARA 룰 엔진 통합
- 사용자 정의 룰 지원
- 고급 패턴 매칭
- 메타데이터 추출

### File System Engine
```rust
// src/engine/filesystem/
├── file_watcher.rs       // 파일 감시
├── file_analyzer.rs      // 파일 분석
└── path_handler.rs       // 경로 처리
```

#### File Watcher
- 실시간 파일 시스템 모니터링
- 이벤트 필터링
- 성능 최적화
- 크로스 플랫폼 지원

#### File Analyzer
- 파일 메타데이터 추출
- MIME 타입 감지
- 압축 파일 처리
- 바이너리 분석

#### Path Handler
- 경로 정규화
- 심볼릭 링크 처리
- 권한 검사
- 플랫폼별 경로 처리

### Signature Engine
```rust
// src/engine/signature/
├── signature_db.rs       // 시그니처 DB 관리
├── signature_updater.rs  // 업데이트 관리
└── hash_engine.rs        // 해시 계산
```

#### Signature Database
- 시그니처 데이터 저장 및 관리
- 인덱싱 및 검색 최적화
- 압축 및 캐싱
- 버전 관리

#### Signature Updater
- 원격 시그니처 데이터베이스 동기화
- 증분 업데이트
- 무결성 검증
- 자동 업데이트 스케줄링

#### Hash Engine
- 다중 해시 알고리즘 지원
- 대용량 파일 처리
- 병렬 처리 최적화
- 체크섬 검증

## Data Layer

### Config Management
```rust
// src/data/config/
├── app_config.rs         // 애플리케이션 설정
└── scan_config.rs        // 스캔 설정
```

#### App Config
- 전역 애플리케이션 설정
- 사용자 프리퍼런스
- 로깅 설정
- 성능 튜닝 매개변수

#### Scan Config
- 스캔 정책 설정
- 제외 경로 및 파일
- 탐지 민감도
- 스캔 옵션

### Storage Management
```rust
// src/data/storage/
├── quarantine_store.rs   // 격리 파일 저장
├── log_store.rs          // 로그 저장
└── report_store.rs       // 리포트 저장
```

#### Quarantine Store
- 격리된 파일 안전 저장
- 메타데이터 관리
- 암호화 및 압축
- 보존 정책

#### Log Store
- 구조화된 로그 저장
- 로그 회전 및 아카이빙
- 검색 및 필터링
- 성능 모니터링

#### Report Store
- 스캔 리포트 생성 및 저장
- 통계 데이터 집계
- 보고서 템플릿
- 내보내기 기능

### Data Models
```rust
// src/data/models/
├── threat.rs             // 위협 모델
├── scan_result.rs        // 스캔 결과 모델
└── config.rs             // 설정 모델
```

#### Threat Model
- 위협 분류 및 메타데이터
- 위험도 계산
- 대응 정책
- 관련 정보

#### Scan Result Model
- 스캔 결과 구조체
- 탐지 정보
- 처리 상태
- 타임스탬프

#### Config Model
- 설정 데이터 구조
- 검증 로직
- 기본값 정의
- 마이그레이션 지원

## 컴포넌트 간 통신

### 이벤트 시스템
- 비동기 이벤트 버스
- 느슨한 결합 보장
- 확장 가능한 이벤트 타입
- 에러 전파 메커니즘

### API 인터페이스
- 표준화된 트레이트 정의
- 의존성 주입 지원
- 모킹 및 테스트 지원
- 버전 호환성

### 데이터 흐름
- 단방향 데이터 플로우
- 상태 관리 최적화
- 캐싱 전략
- 백프레셔 처리