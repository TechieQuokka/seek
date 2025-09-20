# Basic Usage Guide

## Seek 백신 CLI 기본 사용법

Seek 백신 CLI의 현재 구현된 기능들을 상세히 설명합니다.

> **⚠️ 현재 개발 상태**: 이 매뉴얼은 현재 구현된 기능만을 다룹니다. 일부 고급 기능들은 개발 중입니다.

## 📋 목차

1. [스캔 기능 완전 정복](#스캔-기능-완전-정복) ✅ **구현 완료**
2. [출력 형식 및 결과 저장](#출력-형식-및-결과-저장) ✅ **구현 완료**
3. [설정 및 최적화](#설정-및-최적화) ✅ **구현 완료**
4. [개발 중인 기능들](#개발-중인-기능들) ⚠️ **개발 중**

## 🔍 스캔 기능 완전 정복

### 기본 스캔 유형

#### 1. 빠른 스캔 (Quick Scan)
실행 파일과 시스템 핵심 영역만 스캔합니다.

```bash
# 현재 디렉토리 빠른 스캔
seek scan --quick

# 특정 폴더 빠른 스캔
seek scan --quick ./Downloads

# 시스템 중요 영역 빠른 스캔
seek scan --quick /usr/bin /opt /Applications
```

**사용 시기**:
- 매일 정기 검사
- 새로 다운로드한 파일 확인
- 빠른 시스템 상태 점검

#### 2. 전체 스캔 (Full Scan)
모든 파일을 상세히 검사합니다.

```bash
# 전체 시스템 스캔
seek scan --detailed --recursive /

# 홈 디렉토리 전체 스캔
seek scan --detailed --recursive ~/

# 외부 저장장치 전체 스캔
seek scan --detailed --recursive /media/usb-drive
```

**사용 시기**:
- 주간 보안 점검
- 악성코드 감염 의심시
- 시스템 정리 후 확인

#### 3. 사용자 정의 스캔
특정 요구사항에 맞는 맞춤형 스캔입니다.

```bash
# 특정 파일 유형만 스캔
seek scan --include "*.exe,*.dll,*.scr" ./program-files

# 특정 파일 제외하고 스캔
seek scan --exclude "*.log,*.tmp,*.cache" ./workspace

# 특정 파일 직접 스캔
seek scan --file suspicious-file.exe

# 깊이 제한으로 스캔
seek scan --depth 3 --recursive ./deep-folder-structure

# 자동 격리와 함께 스캔 (위험한 파일 발견 시 격리)
seek scan --quarantine ./downloads
```

### 스캔 옵션 상세 가이드

#### 성능 최적화 옵션

```bash
# 멀티스레드 활용 (CPU 코어 수에 맞게 조정)
seek scan --threads 8 ./large-directory

# 상세 출력으로 진행 상황 확인
seek scan --verbose ./large-directory

# 조용한 모드 (최소 출력)
seek scan --quiet ./background-scan
```

#### 파일 필터링 옵션

```bash
# 확장자 기반 필터링 (포함할 파일들)
seek scan --include "*.exe" --include "*.dll" --include "*.scr" ./program-files

# 특정 파일 제외
seek scan --exclude "*.log" --exclude "*.tmp" --exclude "*.cache" ./workspace

# 여러 패턴 조합 사용
seek scan --include "*.exe" --exclude "backup_*" ./downloads
```

## 📄 출력 형식 및 결과 저장

### 지원되는 출력 형식

```bash
# 테이블 형식 (기본값) - 콘솔에서 보기 좋은 형태
seek scan --format table ./folder

# JSON 형식 - 프로그래밍 처리 및 상세 분석용
seek scan --format json ./folder

# HTML 형식 (개발 중)
seek scan --format html ./folder

# CSV 형식 (개발 중)
seek scan --format csv ./folder
```

### 결과 파일 저장

```bash
# JSON 결과를 파일로 저장
seek scan --output scan-report.json --format json ./folder

# 테이블 결과를 텍스트 파일로 저장
seek scan --output scan-summary.txt --format table ./folder
```

### JSON 출력 구조

JSON 출력에는 다음 정보가 포함됩니다:

```json
{
  "id": "스캔 고유 ID",
  "scan_type": "Full",
  "start_time": "시작 시간",
  "end_time": "종료 시간",
  "duration": { "secs": 3, "nanos": 651401200 },
  "target_path": "스캔 대상 경로",
  "summary": {
    "files_scanned": 7,
    "threats_found": 0,
    "errors_encountered": 1,
    "total_size_scanned": 75925234
  },
  "threats": [],
  "errors": [],
  "status": "Completed"
}
```

### 일반적인 스캔 시나리오

#### 시나리오 1: 새 컴퓨터 초기 검사

```bash
# 1단계: 시스템 전체 빠른 검사
seek scan --quick --recursive /

# 2단계: 사용자 데이터 상세 검사
seek scan --detailed ~/Documents ~/Downloads ~/Desktop

# 3단계: 실행 파일 집중 검사
seek scan --include "*.exe,*.dll,*.app" --recursive /Applications /usr/bin
```

#### 시나리오 2: USB/외부 저장장치 검사

```bash
# USB 장치 안전 검사
seek scan --detailed --quarantine /media/usb-device

# 결과 저장 및 리포트 생성
seek scan --output usb-scan-$(date +%Y%m%d).json --format json /media/usb-device
```

#### 시나리오 3: 다운로드 폴더 정기 검사

```bash
# 최근 다운로드 파일만 검사
seek scan --modified-within 1d ~/Downloads

# 압축 파일 내부까지 검사
seek scan --scan-archives ~/Downloads

# 의심스러운 파일 자동 격리
seek scan --quarantine --sensitivity high ~/Downloads
```

#### 시나리오 4: 웹 서버 보안 검사

```bash
# 웹 루트 디렉토리 검사
seek scan --include "*.php,*.js,*.html,*.asp*" /var/www/html

# 업로드 폴더 집중 검사
seek scan --detailed --quarantine /var/www/uploads

# 로그 파일 검사
seek scan --pattern ".*\.(log|access)$" /var/log/apache2
```

## 👁️ 모니터링 및 실시간 보호

### 실시간 모니터링 시작

```bash
# 홈 디렉토리 모니터링 시작
seek monitor start ~/

# 특정 폴더들 모니터링
seek monitor start ~/Downloads ~/Documents ~/Desktop

# 시스템 전체 모니터링 (관리자 권한 필요)
sudo seek monitor start /

# 백그라운드에서 데몬으로 실행
seek monitor start --daemon ~/
```

### 모니터링 설정 옵션

```bash
# 민감도 설정
seek monitor start --sensitivity high ~/Downloads      # 높은 민감도
seek monitor start --sensitivity medium ~/Documents    # 보통 민감도
seek monitor start --sensitivity low ~/Pictures        # 낮은 민감도

# 알림 방법 설정
seek monitor start --alert email ~/critical-folder
seek monitor start --alert desktop ~/Downloads
seek monitor start --alert log ~/system-folder

# 제외 패턴 설정
seek monitor start --exclude "*.tmp,*.log,*.cache" ~/workspace
```

### 모니터링 상태 관리

```bash
# 현재 모니터링 상태 확인
seek monitor status

# 실행 중인 모니터링 작업 목록
seek monitor list

# 특정 모니터링 중지
seek monitor stop ~/Downloads

# 모든 모니터링 중지
seek monitor stop --all

# 모니터링 로그 확인
seek monitor logs --lines 50
seek monitor logs --follow     # 실시간 로그 추적
```

### 실시간 보호 시나리오

#### 시나리오 1: 개발자 워크스페이스 보호

```bash
# 소스 코드 폴더 모니터링
seek monitor start --sensitivity high ~/projects

# 빌드 결과물 폴더 모니터링
seek monitor start --exclude "*.o,*.obj,*.tmp" ~/projects/build

# 다운로드한 라이브러리 모니터링
seek monitor start --alert desktop ~/projects/vendor
```

#### 시나리오 2: 서버 디렉토리 실시간 보호

```bash
# 웹 업로드 폴더 고감도 모니터링
seek monitor start --sensitivity high --alert email /var/www/uploads

# 시스템 바이너리 폴더 보호
seek monitor start --sensitivity high --alert log /usr/bin /usr/sbin

# 설정 파일 디렉토리 모니터링
seek monitor start --alert log /etc
```

## 🔒 격리 파일 관리

### 격리 기본 조작

```bash
# 격리된 파일 목록 확인
seek quarantine list

# 격리된 파일 상세 정보
seek quarantine info <file-id>

# 격리된 파일 복구
seek quarantine restore <file-id>

# 격리된 파일 영구 삭제
seek quarantine delete <file-id>

# 격리 저장소 상태 확인
seek quarantine status
```

### 고급 격리 관리

```bash
# 30일 이상 된 격리 파일 자동 정리
seek quarantine cleanup --older-than 30d

# 격리 저장소 크기 제한 설정
seek quarantine config --max-size 1GB

# 격리 파일 백업
seek quarantine export --output quarantine-backup-$(date +%Y%m%d).tar.gz

# 격리 파일 검색
seek quarantine search --name "*.exe"
seek quarantine search --date "2024-01-01..2024-01-31"
```

### 격리 정책 설정

```bash
# 자동 격리 활성화
seek config set auto-quarantine true

# 격리 대상 위험도 설정
seek config set quarantine-threshold high

# 격리 보존 기간 설정
seek config set quarantine-retention 60d

# 격리 디렉토리 변경
seek config set quarantine-directory /secure/quarantine
```

## 🔄 시그니처 업데이트

### 수동 업데이트

```bash
# 시그니처 업데이트 확인
seek update --check

# 시그니처 다운로드 및 설치
seek update --download

# 강제 업데이트 (캐시 무시)
seek update --force

# 특정 소스에서 업데이트
seek update --source https://custom-signatures.example.com
```

### 자동 업데이트 설정

```bash
# 자동 업데이트 활성화
seek config set auto-update true

# 업데이트 간격 설정 (시간 단위)
seek config set update-interval 6h

# 업데이트 시간 예약
seek schedule add --name "daily-update" --cron "0 2 * * *" "seek update"
```

### 업데이트 상태 관리

```bash
# 현재 시그니처 버전 확인
seek status signatures

# 업데이트 이력 확인
seek update history

# 업데이트 로그 확인
seek update logs

# 시그니처 무결성 검증
seek update verify
```

## ⏰ 일정 관리 및 자동화

### 스캔 일정 생성

```bash
# 매일 새벽 2시 홈 디렉토리 스캔
seek schedule add --name "daily-home-scan" \
    --cron "0 2 * * *" \
    "seek scan --quick ~/"

# 매주 일요일 전체 시스템 스캔
seek schedule add --name "weekly-full-scan" \
    --cron "0 3 * * 0" \
    "seek scan --detailed --recursive /"

# 매일 다운로드 폴더 검사
seek schedule add --name "download-check" \
    --cron "*/30 * * * *" \
    "seek scan --quarantine ~/Downloads"
```

### 일정 관리

```bash
# 등록된 일정 목록 확인
seek schedule list

# 특정 일정 상세 정보
seek schedule info daily-home-scan

# 일정 활성화/비활성화
seek schedule enable daily-home-scan
seek schedule disable weekly-full-scan

# 일정 삭제
seek schedule remove daily-home-scan

# 일정 수정
seek schedule modify daily-home-scan --cron "0 3 * * *"
```

### 복합 자동화 시나리오

#### 시나리오 1: 종합 보안 관리 자동화

```bash
# 1. 매일 새벽 시그니처 업데이트
seek schedule add --name "update-signatures" \
    --cron "0 1 * * *" \
    "seek update"

# 2. 매일 오전 중요 폴더 스캔
seek schedule add --name "morning-scan" \
    --cron "0 8 * * 1-5" \
    "seek scan --quick ~/Documents ~/Downloads"

# 3. 매주 전체 시스템 검사
seek schedule add --name "weekend-full-scan" \
    --cron "0 2 * * 6" \
    "seek scan --detailed --recursive / --output weekly-report.json"

# 4. 매월 격리 파일 정리
seek schedule add --name "monthly-cleanup" \
    --cron "0 4 1 * *" \
    "seek quarantine cleanup --older-than 30d"
```

#### 시나리오 2: 서버 보안 자동화

```bash
# 웹 서버 디렉토리 정기 검사
seek schedule add --name "web-security-scan" \
    --cron "0 */6 * * *" \
    "seek scan --detailed /var/www"

# 로그 파일 분석
seek schedule add --name "log-analysis" \
    --cron "0 5 * * *" \
    "seek scan --pattern '.*malware.*' /var/log"

# 시스템 바이너리 무결성 검사
seek schedule add --name "binary-integrity" \
    --cron "0 3 * * 1" \
    "seek scan --detailed /usr/bin /usr/sbin"
```

## 📊 결과 분석 및 리포팅

### 스캔 결과 분석

```bash
# JSON 형식으로 상세 분석
seek scan --format json ./folder | jq '.threats[] | select(.risk_level == "high")'

# CSV 형식으로 엑셀 분석용 데이터 생성
seek scan --format csv --output analysis.csv ./folder

# 시간대별 스캔 성능 분석
seek scan --benchmark --output performance.json ./folder
```

### 리포트 생성

```bash
# 주간 보안 리포트 생성
seek report generate --type weekly --output weekly-security-report.pdf

# 월간 위협 동향 리포트
seek report generate --type monthly --include-trends ./reports/

# 시스템 상태 요약 리포트
seek status --detailed --output system-status.json
```

### 통계 및 대시보드

```bash
# 스캔 통계 확인
seek stats scan --period 30d

# 위협 탐지 통계
seek stats threats --group-by type

# 성능 통계
seek stats performance --show-trends

# 시간대별 활동 통계
seek stats activity --hourly --last 7d
```

### 로그 분석

```bash
# 최근 스캔 로그 확인
seek logs scan --since "1 week ago"

# 에러 로그만 필터링
seek logs --level error --since "1 day ago"

# 특정 패턴으로 로그 검색
seek logs --pattern "quarantine" --since "1 month ago"

# 로그 내보내기
seek logs export --format json --output logs-$(date +%Y%m%d).json
```

## 🛠️ 설정 및 최적화

### 기본 설정 관리

```bash
# 현재 설정 확인
seek config show

# 특정 설정 값 확인
seek config get scan.max-threads

# 설정 값 변경
seek config set scan.max-threads 8
seek config set quarantine.auto-delete false

# 설정 파일 위치 확인
seek config path

# 설정 초기화
seek config reset
```

### 성능 최적화 설정

```bash
# CPU 사용량 최적화
seek config set performance.max-cpu-usage 80%
seek config set performance.thread-priority normal

# 메모리 사용량 최적화
seek config set performance.max-memory 2GB
seek config set performance.cache-size 256MB

# 디스크 I/O 최적화
seek config set performance.io-priority low
seek config set performance.read-buffer-size 64KB
```

### 네트워크 설정

```bash
# 프록시 설정
seek config set network.proxy http://proxy.company.com:8080
seek config set network.proxy-auth username:password

# 업데이트 서버 설정
seek config set network.update-server https://updates.seek-av.com
seek config set network.backup-servers https://backup.seek-av.com

# 타임아웃 설정
seek config set network.connect-timeout 30s
seek config set network.read-timeout 60s
```

## 🎯 일상 운영 체크리스트

### 매일 할 일

- [ ] `seek monitor status` - 실시간 보호 상태 확인
- [ ] `seek scan --quick ~/Downloads` - 다운로드 폴더 빠른 검사
- [ ] `seek quarantine list` - 격리 파일 상태 확인

### 매주 할 일

- [ ] `seek scan --detailed ~/` - 홈 디렉토리 전체 검사
- [ ] `seek update --check` - 시그니처 업데이트 확인
- [ ] `seek logs scan --since "1 week ago"` - 주간 로그 검토

### 매월 할 일

- [ ] `seek scan --detailed --recursive /` - 시스템 전체 검사
- [ ] `seek quarantine cleanup --older-than 30d` - 격리 파일 정리
- [ ] `seek report generate --type monthly` - 월간 보안 리포트 생성
- [ ] `seek config backup` - 설정 백업

## 📚 다음 단계

기본 사용법을 숙지하셨다면 다음 문서를 참고하세요:

- **[심화 사용법](advanced-usage.md)**: 고급 기능 및 커스터마이징
- **[예제 모음](examples/)**: 실제 사용 시나리오 예제
- **[문제 해결](../docs/troubleshooting.md)**: 일반적인 문제 해결 방법

---

**이제 Seek 백신 CLI의 주요 기능들을 효과적으로 활용할 수 있습니다! 🚀**