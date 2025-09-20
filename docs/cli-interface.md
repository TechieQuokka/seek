# CLI 인터페이스 설계

## 개요
Seek 백신 CLI는 직관적이고 강력한 명령어 인터페이스를 제공합니다. clap 라이브러리를 활용하여 현대적인 CLI 경험을 구현합니다.

## 메인 명령어 구조

```bash
seek --help

USAGE:
    seek [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -c, --config <FILE>    설정 파일 경로
    -v, --verbose          상세 출력 모드
    -q, --quiet            조용한 모드
    -h, --help             도움말 출력
    --version              버전 정보 출력

SUBCOMMANDS:
    scan        파일 및 디렉토리 스캔
    monitor     실시간 모니터링 시작/중지
    quarantine  격리된 파일 관리
    update      시그니처 데이터베이스 업데이트
    schedule    스캔 스케줄 관리
    config      설정 관리
    report      스캔 리포트 조회
    status      시스템 상태 확인
```

## 세부 명령어

### Scan 명령어
```bash
seek scan --help

USAGE:
    seek scan [OPTIONS] [PATH]

ARGUMENTS:
    <PATH>    스캔할 경로 (기본값: 현재 디렉토리)

OPTIONS:
    -r, --recursive           하위 디렉토리 포함 스캔
    -f, --file <FILE>         특정 파일 스캔
    -d, --depth <DEPTH>       스캔 깊이 제한
    -q, --quarantine          위협 발견 시 자동 격리
    -t, --threads <NUMBER>    스캔 스레드 수
    --exclude <PATTERN>       제외할 파일/경로 패턴
    --include <PATTERN>       포함할 파일/경로 패턴
    --detailed                상세 스캔 모드
    --quick                   빠른 스캔 모드
    --format <FORMAT>         출력 형식 (json, table, csv)
    -o, --output <FILE>       결과를 파일로 저장

EXAMPLES:
    seek scan                           # 현재 디렉토리 스캔
    seek scan /home/user                # 특정 디렉토리 스캔
    seek scan --file suspicious.exe    # 특정 파일 스캔
    seek scan -r --quarantine /home    # 재귀 스캔 + 자동 격리
    seek scan --exclude "*.tmp"        # 임시 파일 제외
    seek scan --format json -o report.json  # JSON 형식으로 저장
```

### Monitor 명령어
```bash
seek monitor --help

USAGE:
    seek monitor <SUBCOMMAND>

SUBCOMMANDS:
    start     실시간 모니터링 시작
    stop      실시간 모니터링 중지
    status    모니터링 상태 확인
    logs      모니터링 로그 조회

# 모니터링 시작
seek monitor start --help

USAGE:
    seek monitor start [OPTIONS] [PATH]

ARGUMENTS:
    <PATH>    모니터링할 경로 (기본값: 전체 시스템)

OPTIONS:
    --daemon              백그라운드에서 실행
    --alert <METHOD>      알림 방법 (email, desktop, log)
    --exclude <PATTERN>   제외할 파일/경로 패턴
    --sensitivity <LEVEL> 탐지 민감도 (low, medium, high)

EXAMPLES:
    seek monitor start /home/user       # 특정 경로 모니터링
    seek monitor start --daemon         # 백그라운드 모니터링
    seek monitor stop                   # 모니터링 중지
    seek monitor status                 # 상태 확인
```

### Quarantine 명령어
```bash
seek quarantine --help

USAGE:
    seek quarantine <SUBCOMMAND>

SUBCOMMANDS:
    list      격리된 파일 목록
    restore   격리된 파일 복구
    delete    격리된 파일 삭제
    info      격리 파일 상세 정보

EXAMPLES:
    seek quarantine list                # 격리 파일 목록
    seek quarantine restore <FILE_ID>   # 파일 복구
    seek quarantine delete <FILE_ID>    # 파일 삭제
    seek quarantine info <FILE_ID>      # 상세 정보
```

### Update 명령어
```bash
seek update --help

USAGE:
    seek update [OPTIONS]

OPTIONS:
    --check     업데이트 확인만 수행
    --download  시그니처 다운로드
    --force     강제 업데이트
    --source <URL>  사용자 정의 업데이트 소스

EXAMPLES:
    seek update --check      # 업데이트 확인
    seek update              # 시그니처 업데이트
    seek update --force      # 강제 업데이트
```

### Schedule 명령어
```bash
seek schedule --help

USAGE:
    seek schedule <SUBCOMMAND>

SUBCOMMANDS:
    add     새 스케줄 추가
    list    스케줄 목록
    remove  스케줄 제거
    enable  스케줄 활성화
    disable 스케줄 비활성화

# 스케줄 추가
seek schedule add --help

USAGE:
    seek schedule add [OPTIONS] --name <NAME> --path <PATH>

OPTIONS:
    --name <NAME>         스케줄 이름
    --path <PATH>         스캔 경로
    --daily               매일 실행
    --weekly              매주 실행
    --monthly             매월 실행
    --time <TIME>         실행 시간 (HH:MM 형식)
    --cron <EXPRESSION>   크론 표현식

EXAMPLES:
    seek schedule add --name "daily-scan" --path /home --daily --time 02:00
    seek schedule add --name "weekly-full" --path / --weekly --time 01:00
    seek schedule list
    seek schedule remove daily-scan
```

### Config 명령어
```bash
seek config --help

USAGE:
    seek config <SUBCOMMAND>

SUBCOMMANDS:
    show    현재 설정 표시
    set     설정 값 변경
    reset   설정 초기화
    export  설정 내보내기
    import  설정 가져오기

EXAMPLES:
    seek config show                    # 전체 설정 표시
    seek config set scan.threads 4     # 스캔 스레드 수 설정
    seek config reset                   # 설정 초기화
    seek config export config.toml     # 설정 내보내기
```

### Report 명령어
```bash
seek report --help

USAGE:
    seek report [OPTIONS]

OPTIONS:
    --type <TYPE>         리포트 타입 (scan, threat, system)
    --format <FORMAT>     출력 형식 (table, json, html)
    --period <PERIOD>     기간 (day, week, month)
    --output <FILE>       출력 파일
    --filter <FILTER>     필터 조건

EXAMPLES:
    seek report --type scan --period week    # 주간 스캔 리포트
    seek report --type threat --format json  # 위협 리포트 JSON
    seek report --filter "severity>=high"    # 고위험 위협만
```

### Status 명령어
```bash
seek status --help

USAGE:
    seek status [OPTIONS]

OPTIONS:
    --watch     실시간 상태 모니터링
    --json      JSON 형식 출력

EXAMPLES:
    seek status          # 현재 상태 표시
    seek status --watch  # 실시간 상태 모니터링
    seek status --json   # JSON 형식 출력
```

## 출력 형식

### 기본 테이블 형식
```
┌─────────────────────────────────────────────────────────────┐
│                        Scan Results                         │
├─────────────────────────────────────────────────────────────┤
│ File: /suspicious/file.exe                                  │
│ Status: THREAT DETECTED                                     │
│ Threat: Trojan.Generic.12345                               │
│ Action: QUARANTINED                                         │
│ Time: 2024-01-15 14:30:22                                  │
└─────────────────────────────────────────────────────────────┘

Scan Summary:
  Files Scanned: 1,234
  Threats Found: 3
  Quarantined: 3
  Errors: 0
  Duration: 45.2s
```

### JSON 형식
```json
{
  "scan_id": "scan-2024-01-15-14-30",
  "start_time": "2024-01-15T14:30:00Z",
  "end_time": "2024-01-15T14:30:45Z",
  "duration": 45.2,
  "summary": {
    "files_scanned": 1234,
    "threats_found": 3,
    "quarantined": 3,
    "errors": 0
  },
  "threats": [
    {
      "file_path": "/suspicious/file.exe",
      "threat_name": "Trojan.Generic.12345",
      "severity": "high",
      "action": "quarantined",
      "detection_time": "2024-01-15T14:30:22Z"
    }
  ]
}
```

## 진행률 표시

### 스캔 진행률
```
Scanning: /home/user/documents
Progress: [████████████████████████████████] 100% (1234/1234 files)
Speed: 45.2 files/sec | Elapsed: 00:00:27 | ETA: 00:00:00
Current: document.pdf (safe)
```

### 업데이트 진행률
```
Updating virus signatures...
Download: [████████████████████████████████] 100% (15.2 MB/15.2 MB)
Verifying: [████████████████████████████████] 100%
Installing: [████████████████████████████████] 100%
Update completed successfully.
```

## 에러 처리

### 사용자 친화적 에러 메시지
```bash
# 권한 부족
Error: Permission denied accessing '/root/secret'
Suggestion: Run with elevated privileges or exclude this path

# 파일을 찾을 수 없음
Error: Path '/nonexistent' does not exist
Suggestion: Check the path and try again

# 설정 오류
Error: Invalid configuration in 'scan.threads': value must be between 1 and 16
Suggestion: Use 'seek config set scan.threads <number>' to fix
```

## 색상 및 스타일

### 색상 코딩
- **녹색**: 안전한 파일, 성공적인 작업
- **빨간색**: 위협 탐지, 에러
- **노란색**: 경고, 의심스러운 활동
- **파란색**: 정보, 진행 상황
- **회색**: 비활성화된 항목

### 아이콘 사용
- ✅ 안전
- ⚠️ 경고
- ❌ 위험
- 🔍 스캔 중
- 📁 디렉토리
- 📄 파일
- 🛡️ 보호됨