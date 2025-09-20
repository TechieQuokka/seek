# Getting Started Guide

## Seek 백신 CLI 처음 사용자 가이드

Seek 백신 CLI를 처음 사용하시는 분들을 위한 단계별 가이드입니다.

## 📋 목차

1. [설치 및 설정](#설치-및-설정)
2. [첫 번째 스캔 실행](#첫-번째-스캔-실행)
3. [기본 명령어 익히기](#기본-명령어-익히기)
4. [결과 해석하기](#결과-해석하기)
5. [다음 단계](#다음-단계)

## 🚀 설치 및 설정

### 시스템 요구사항

- **운영체제**: Windows 10+, macOS 10.15+, Ubuntu 18.04+
- **메모리**: 최소 512MB RAM
- **저장공간**: 100MB 이상 여유 공간
- **Rust**: 1.70.0 이상 (개발자용)

### 설치 방법

#### 방법 1: 사전 빌드된 바이너리 사용 (권장)

```bash
# GitHub 릴리스에서 다운로드
curl -L -o seek.zip https://github.com/TechieQuokka/seek/releases/latest/download/seek-windows-x64.zip
unzip seek.zip
./seek --version
```

#### 방법 2: 소스에서 빌드

```bash
# 저장소 복제
git clone https://github.com/TechieQuokka/seek.git
cd seek

# 빌드 및 설치
cargo build --release
./target/release/seek --version
```

### 첫 실행 확인

설치가 완료되면 다음 명령어로 정상 작동을 확인하세요:

```bash
seek --help
```

정상적으로 설치되었다면 다음과 같은 도움말이 표시됩니다:

```
Seek - Rust 백신 CLI

고성능 Rust로 개발된 백신 CLI 도구

Usage: seek <COMMAND>

Commands:
  scan        파일 및 디렉토리 스캔
  monitor     실시간 모니터링
  quarantine  격리 파일 관리
  update      시그니처 업데이트
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## 🔍 첫 번째 스캔 실행

### 1단계: 안전한 테스트 스캔

처음에는 작은 폴더나 단일 파일로 테스트해보세요:

```bash
# 현재 디렉토리의 빠른 스캔
seek scan --quick

# 특정 파일 스캔
seek scan --file README.md

# 특정 폴더 스캔 (재귀적이지 않음)
seek scan ./documents
```

### 2단계: 결과 확인

스캔이 완료되면 다음과 같은 결과가 표시됩니다:

```
🔍 스캔 시작: /home/user/documents
📁 스캔된 파일: 15개
⏱️  스캔 시간: 2.3초
✅ 안전한 파일: 15개
⚠️  위협 발견: 0개

스캔 완료 - 위협이 발견되지 않았습니다
```

### 3단계: EICAR 테스트 파일로 검증

백신이 정상 작동하는지 확인하기 위해 무해한 테스트 파일을 사용해보세요:

```bash
# EICAR 테스트 파일 생성 (완전히 안전함)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > test-virus.txt

# 테스트 파일 스캔
seek scan --file test-virus.txt
```

정상 작동시 다음과 같이 표시됩니다:

```
🚨 위협 발견!
📄 파일: test-virus.txt
🦠 위협 유형: EICAR-Test-File
🔒 위험도: 높음
📊 신뢰도: 100%

위협이 1개 발견되었습니다.
```

## 🎯 기본 명령어 익히기

### 도움말 보기

언제든지 도움말을 확인할 수 있습니다:

```bash
# 전체 도움말
seek --help

# 특정 명령어 도움말
seek scan --help
seek monitor --help
```

### 스캔 명령어 기본 사용법

```bash
# 1. 빠른 스캔 (권장 시작)
seek scan --quick

# 2. 상세 스캔
seek scan --detailed

# 3. 재귀적 디렉토리 스캔
seek scan --recursive ./my-folder

# 4. 결과를 파일로 저장
seek scan --output scan-result.json --format json
```

### 출력 형식 변경

```bash
# 테이블 형식 (기본값)
seek scan --format table

# JSON 형식
seek scan --format json

# 간단한 텍스트 형식
seek scan --format text
```

## 📊 결과 해석하기

### 스캔 결과 구성 요소

1. **파일 정보**
   - 스캔된 파일 경로
   - 파일 크기 및 타입
   - 마지막 수정 시간

2. **위협 정보** (발견된 경우)
   - 위협 이름 및 유형
   - 위험도 등급 (낮음/보통/높음/심각)
   - 탐지 신뢰도 (0-100%)

3. **스캔 통계**
   - 총 스캔 파일 수
   - 소요 시간
   - 발견된 위협 수

### 위험도 등급 이해

- 🟢 **낮음**: 의심스러운 패턴, 추가 검토 권장
- 🟡 **보통**: 잠재적 위험, 주의 필요
- 🟠 **높음**: 알려진 악성 패턴, 격리 권장
- 🔴 **심각**: 확실한 악성 파일, 즉시 격리 필요

### 일반적인 결과 시나리오

#### 시나리오 1: 깨끗한 시스템
```
✅ 스캔 완료 - 위협이 발견되지 않았습니다
📁 스캔된 파일: 1,234개
⏱️  총 시간: 45.2초
```

#### 시나리오 2: 위협 발견
```
⚠️  위협 발견!
📄 파일: suspicious-file.exe
🦠 위협: Trojan.Generic.12345
🔒 위험도: 높음
💡 권장사항: 즉시 격리하거나 삭제하세요
```

#### 시나리오 3: 의심스러운 파일
```
🔍 의심스러운 파일 발견
📄 파일: unknown-script.ps1
⚠️  패턴: 의심스러운 PowerShell 명령어
🔒 위험도: 보통
💡 권장사항: 출처를 확인하고 신뢰할 수 있는 경우에만 실행하세요
```

## ⚠️ 주의사항

### 해야 할 것

✅ **정기적인 스캔**: 주 1-2회 전체 시스템 스캔
✅ **시그니처 업데이트**: 정기적으로 `seek update` 실행
✅ **결과 검토**: 각 스캔 결과를 주의 깊게 확인
✅ **백업**: 중요한 파일은 스캔 전 백업

### 하지 말아야 할 것

❌ **무분별한 삭제**: 확실하지 않은 파일 함부로 삭제 금지
❌ **시스템 파일 스캔**: OS 핵심 파일 스캔 시 주의
❌ **격리 무시**: 위험한 파일 발견 시 격리 조치 무시 금지
❌ **과도한 스캔**: 동일 파일 반복 스캔으로 시스템 부하 증가 금지

## 🛠️ 문제 해결

### 일반적인 문제와 해결방법

#### 문제 1: "권한 거부" 오류
```bash
# 해결방법: 관리자 권한으로 실행
sudo seek scan /system-folder  # Linux/macOS
# 또는 관리자 권한 CMD에서 실행 (Windows)
```

#### 문제 2: 스캔이 너무 느림
```bash
# 해결방법: 스레드 수 조정
seek scan --threads 4 --quick
```

#### 문제 3: 메모리 부족
```bash
# 해결방법: 작은 청크로 나누어 스캔
seek scan --max-file-size 50MB ./large-folder
```

### 로그 확인

문제 발생 시 상세 로그를 확인할 수 있습니다:

```bash
# 상세 로그와 함께 실행
RUST_LOG=debug seek scan ./folder

# 로그 파일로 저장
seek scan ./folder 2> scan.log
```

## 📚 다음 단계

처음 사용자 가이드를 완료하셨다면 다음 문서들을 참고하세요:

1. **[기본 사용법](basic-usage.md)**: 일상적인 사용을 위한 상세 가이드
2. **[심화 사용법](advanced-usage.md)**: 고급 기능 및 설정
3. **[예제 모음](examples/)**: 다양한 사용 시나리오 예제

## 💬 도움 받기

- **GitHub Issues**: [버그 리포트 및 기능 요청](https://github.com/TechieQuokka/seek/issues)
- **문서**: [전체 문서 보기](../docs/)
- **예제**: [실제 사용 예제](examples/)

---

**축하합니다! 🎉 이제 Seek 백신 CLI의 기본 사용법을 익히셨습니다.**

다음 단계로 [기본 사용법 가이드](basic-usage.md)를 확인해보세요.